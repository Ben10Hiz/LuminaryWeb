/**
 * Luminary Communications API
 * Node.js + Express + MongoDB + Cloudflare R2
 * 
 * Deploy to: Railway, Render, or any Node.js host
 */

const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== CONFIGURATION =====
const config = {
    mongoUri: process.env.MONGODB_URI,
    jwtSecret: process.env.JWT_SECRET || 'luminary-jwt-secret-change-in-production',
    adminPassword: process.env.ADMIN_PASSWORD || 'Luminary2025!Command',
    dbName: 'luminary_comms',
    // R2 Configuration
    r2: {
        endpoint: process.env.R2_ENDPOINT || 'https://0789a7e56a4c10beb992cbd3cf8ed6e5.r2.cloudflarestorage.com',
        accessKeyId: process.env.R2_ACCESS_KEY_ID || '70e29c014ff3ddaa8c34e87eb5123d7f',
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY || '8b5664f90c958ca68f6f28f495f1daaf3b2eb27e559678429f3dc9a271273d59',
        bucket: process.env.R2_BUCKET || 'luminary-files',
        publicUrl: process.env.R2_PUBLIC_URL || '' // Will be set after enabling public access
    }
};

// ===== R2 CLIENT =====
const r2Client = new S3Client({
    region: 'auto',
    endpoint: config.r2.endpoint,
    credentials: {
        accessKeyId: config.r2.accessKeyId,
        secretAccessKey: config.r2.secretAccessKey
    }
});

// ===== MIDDLEWARE =====
app.use(cors());
app.use(express.json({ limit: '50mb' })); // Increased for file attachments

// Request logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
    next();
});

// ===== DATABASE =====
let db;
let client;

async function connectDB() {
    if (db) return db;
    
    if (!config.mongoUri) {
        throw new Error('MONGODB_URI environment variable is required');
    }
    
    client = new MongoClient(config.mongoUri);
    await client.connect();
    db = client.db(config.dbName);
    
    console.log('✓ Connected to MongoDB');
    
    // Create indexes
    await db.collection('partners').createIndex({ id: 1 }, { unique: true });
    await db.collection('partners').createIndex({ recipientType: 1 });
    await db.collection('partners').createIndex({ status: 1 });
    await db.collection('partners').createIndex({ lastActivity: -1 });
    await db.collection('messages').createIndex({ partnerId: 1, date: 1 });
    await db.collection('messages').createIndex({ fromLuminary: 1, read: 1 });
    await db.collection('files').createIndex({ fileId: 1 }, { unique: true });
    await db.collection('files').createIndex({ partnerId: 1 });
    await db.collection('files').createIndex({ uploadedAt: -1 });
    
    console.log('✓ Database indexes created');
    
    return db;
}

// ===== HELPERS =====

function hashPassword(password) {
    return crypto.createHash('sha256')
        .update(password + 'luminary-salt-2025')
        .digest('hex');
}

function generateToken(payload) {
    return jwt.sign(payload, config.jwtSecret, { expiresIn: '24h' });
}

function verifyToken(token) {
    try {
        return jwt.verify(token, config.jwtSecret);
    } catch (e) {
        return null;
    }
}

// Auth middleware
function requireAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authorization required' });
    }
    
    const token = authHeader.substring(7);
    const payload = verifyToken(token);
    
    if (!payload) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
    req.admin = payload;
    next();
}

// ===== ROUTES =====

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        database: db ? 'connected' : 'disconnected'
    });
});

// Admin login
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    
    if (!password) {
        return res.status(400).json({ error: 'Password required' });
    }
    
    // Check password
    if (password !== config.adminPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = generateToken({ role: 'admin' });
    
    res.json({ 
        token, 
        expiresIn: 86400 // 24 hours
    });
});

// Validate partner key (public)
app.post('/api/validate-key', async (req, res) => {
    try {
        const { key } = req.body;
        
        if (!key || key.length !== 15) {
            return res.status(400).json({ error: 'Invalid key format' });
        }
        
        // Find partner
        const partner = await db.collection('partners').findOne({ id: key });
        
        if (!partner) {
            return res.status(404).json({ error: 'Invalid key' });
        }
        
        // Update status if pending
        if (partner.status === 'pending') {
            await db.collection('partners').updateOne(
                { id: key },
                { 
                    $set: { 
                        status: 'viewed',
                        lastActivity: new Date().toISOString()
                    }
                }
            );
            partner.status = 'viewed';
        }
        
        // Get messages
        const messages = await db.collection('messages')
            .find({ partnerId: key })
            .sort({ date: 1 })
            .toArray();
        
        partner.messages = messages;
        
        // Remove MongoDB _id from response
        delete partner._id;
        partner.messages = partner.messages.map(m => {
            delete m._id;
            return m;
        });
        
        res.json(partner);
        
    } catch (error) {
        console.error('Validate key error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== FILE UPLOAD =====

// Upload file to R2 (public - for partners)
app.post('/api/files/upload', async (req, res) => {
    try {
        const { key, filename, contentType, data, size } = req.body;
        
        if (!key || !filename || !data) {
            return res.status(400).json({ error: 'Key, filename, and data required' });
        }
        
        // Verify partner exists
        const partner = await db.collection('partners').findOne({ id: key });
        if (!partner) {
            return res.status(404).json({ error: 'Invalid key' });
        }
        
        // Generate unique file ID
        const fileId = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;
        const fileKey = `partners/${key}/${fileId}-${filename.replace(/[^a-zA-Z0-9.-]/g, '_')}`;
        
        // Extract base64 data (remove data URL prefix if present)
        const base64Data = data.includes(',') ? data.split(',')[1] : data;
        const buffer = Buffer.from(base64Data, 'base64');
        
        // Upload to R2
        await r2Client.send(new PutObjectCommand({
            Bucket: config.r2.bucket,
            Key: fileKey,
            Body: buffer,
            ContentType: contentType || 'application/octet-stream',
            Metadata: {
                partnerId: key,
                originalName: filename,
                uploadedAt: new Date().toISOString()
            }
        }));
        
        // Generate public URL (using R2 public URL or signed URL)
        let fileUrl;
        if (config.r2.publicUrl) {
            fileUrl = `${config.r2.publicUrl}/${fileKey}`;
        } else {
            // Generate a long-lived signed URL (7 days) as fallback
            fileUrl = await getSignedUrl(r2Client, new GetObjectCommand({
                Bucket: config.r2.bucket,
                Key: fileKey
            }), { expiresIn: 7 * 24 * 60 * 60 });
        }
        
        // Store file metadata in database
        const fileDoc = {
            fileId,
            fileKey,
            partnerId: key,
            filename,
            contentType: contentType || 'application/octet-stream',
            size: size || buffer.length,
            url: fileUrl,
            uploadedAt: new Date().toISOString(),
            uploadedBy: 'partner'
        };
        
        await db.collection('files').insertOne(fileDoc);
        
        console.log(`✓ File uploaded: ${fileKey}`);
        
        res.json({
            success: true,
            fileId,
            url: fileUrl,
            filename,
            size: fileDoc.size
        });
        
    } catch (error) {
        console.error('File upload error:', error);
        res.status(500).json({ error: 'Failed to upload file' });
    }
});

// Upload file (admin)
app.post('/api/admin/files/upload', requireAdmin, async (req, res) => {
    try {
        const { partnerId, filename, contentType, data, size } = req.body;
        
        if (!partnerId || !filename || !data) {
            return res.status(400).json({ error: 'Partner ID, filename, and data required' });
        }
        
        // Generate unique file ID
        const fileId = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;
        const fileKey = `admin/${partnerId}/${fileId}-${filename.replace(/[^a-zA-Z0-9.-]/g, '_')}`;
        
        // Extract base64 data
        const base64Data = data.includes(',') ? data.split(',')[1] : data;
        const buffer = Buffer.from(base64Data, 'base64');
        
        // Upload to R2
        await r2Client.send(new PutObjectCommand({
            Bucket: config.r2.bucket,
            Key: fileKey,
            Body: buffer,
            ContentType: contentType || 'application/octet-stream',
            Metadata: {
                partnerId,
                originalName: filename,
                uploadedAt: new Date().toISOString(),
                uploadedBy: 'admin'
            }
        }));
        
        // Generate URL
        let fileUrl;
        if (config.r2.publicUrl) {
            fileUrl = `${config.r2.publicUrl}/${fileKey}`;
        } else {
            fileUrl = await getSignedUrl(r2Client, new GetObjectCommand({
                Bucket: config.r2.bucket,
                Key: fileKey
            }), { expiresIn: 7 * 24 * 60 * 60 });
        }
        
        // Store file metadata
        const fileDoc = {
            fileId,
            fileKey,
            partnerId,
            filename,
            contentType: contentType || 'application/octet-stream',
            size: size || buffer.length,
            url: fileUrl,
            uploadedAt: new Date().toISOString(),
            uploadedBy: 'admin'
        };
        
        await db.collection('files').insertOne(fileDoc);
        
        console.log(`✓ Admin file uploaded: ${fileKey}`);
        
        res.json({
            success: true,
            fileId,
            url: fileUrl,
            filename,
            size: fileDoc.size
        });
        
    } catch (error) {
        console.error('Admin file upload error:', error);
        res.status(500).json({ error: 'Failed to upload file' });
    }
});

// Get file URL (refresh signed URL if needed)
app.get('/api/files/:fileId', async (req, res) => {
    try {
        const file = await db.collection('files').findOne({ fileId: req.params.fileId });
        
        if (!file) {
            return res.status(404).json({ error: 'File not found' });
        }
        
        // If using signed URLs and it might be expired, generate a new one
        if (!config.r2.publicUrl) {
            const newUrl = await getSignedUrl(r2Client, new GetObjectCommand({
                Bucket: config.r2.bucket,
                Key: file.fileKey
            }), { expiresIn: 7 * 24 * 60 * 60 });
            
            // Update stored URL
            await db.collection('files').updateOne(
                { fileId: req.params.fileId },
                { $set: { url: newUrl } }
            );
            
            file.url = newUrl;
        }
        
        res.json(file);
        
    } catch (error) {
        console.error('Get file error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Partner sends message (public)
app.post('/api/dialogue/respond', async (req, res) => {
    try {
        const { key, content, attachments } = req.body;
        
        if (!key || (!content && (!attachments || attachments.length === 0))) {
            return res.status(400).json({ error: 'Key and content or attachments required' });
        }
        
        // Verify partner exists
        const partner = await db.collection('partners').findOne({ id: key });
        
        if (!partner) {
            return res.status(404).json({ error: 'Invalid key' });
        }
        
        // Create message with optional attachments
        const message = {
            id: `msg_${Date.now()}`,
            partnerId: key,
            content: content || '(File attachment)',
            fromLuminary: false,
            read: false,
            date: new Date().toISOString(),
            attachments: attachments || []
        };
        
        await db.collection('messages').insertOne(message);
        
        // Update partner status
        await db.collection('partners').updateOne(
            { id: key },
            {
                $set: {
                    status: 'responded',
                    lastActivity: new Date().toISOString()
                }
            }
        );
        
        delete message._id;
        res.json({ success: true, message });
        
    } catch (error) {
        console.error('Partner respond error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get all partners (admin)
app.get('/api/admin/partners', requireAdmin, async (req, res) => {
    try {
        // Get all partners
        const partners = await db.collection('partners')
            .find({})
            .sort({ lastActivity: -1 })
            .limit(1000)
            .toArray();
        
        // Get all messages
        const messages = await db.collection('messages')
            .find({})
            .sort({ date: 1 })
            .toArray();
        
        // Group messages by partnerId
        const messagesByPartner = {};
        messages.forEach(msg => {
            if (!messagesByPartner[msg.partnerId]) {
                messagesByPartner[msg.partnerId] = [];
            }
            delete msg._id;
            messagesByPartner[msg.partnerId].push(msg);
        });
        
        // Attach messages to partners
        const result = partners.map(p => {
            delete p._id;
            p.messages = messagesByPartner[p.id] || [];
            return p;
        });
        
        res.json(result);
        
    } catch (error) {
        console.error('Get partners error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get single partner (admin)
app.get('/api/admin/partners/:id', requireAdmin, async (req, res) => {
    try {
        const partner = await db.collection('partners').findOne({ id: req.params.id });
        
        if (!partner) {
            return res.status(404).json({ error: 'Partner not found' });
        }
        
        const messages = await db.collection('messages')
            .find({ partnerId: req.params.id })
            .sort({ date: 1 })
            .toArray();
        
        delete partner._id;
        partner.messages = messages.map(m => {
            delete m._id;
            return m;
        });
        
        res.json(partner);
        
    } catch (error) {
        console.error('Get partner error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin sends message
app.post('/api/admin/messages', requireAdmin, async (req, res) => {
    try {
        const { partnerId, content, attachments } = req.body;
        
        if (!partnerId || (!content && (!attachments || attachments.length === 0))) {
            return res.status(400).json({ error: 'Partner ID and content or attachments required' });
        }
        
        const message = {
            id: `msg_${Date.now()}`,
            partnerId,
            content: content || '(File attachment)',
            fromLuminary: true,
            date: new Date().toISOString(),
            attachments: attachments || []
        };
        
        await db.collection('messages').insertOne(message);
        
        // Update partner activity
        await db.collection('partners').updateOne(
            { id: partnerId },
            { $set: { lastActivity: new Date().toISOString() } }
        );
        
        delete message._id;
        res.json({ success: true, message });
        
    } catch (error) {
        console.error('Admin message error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete message (admin)
app.delete('/api/admin/messages/:id', requireAdmin, async (req, res) => {
    try {
        const result = await db.collection('messages').deleteOne({ id: req.params.id });
        res.json({ success: true, deletedCount: result.deletedCount });
    } catch (error) {
        console.error('Delete message error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Mark messages as read (admin)
app.post('/api/admin/messages/read', requireAdmin, async (req, res) => {
    try {
        const { partnerId } = req.body;
        
        await db.collection('messages').updateMany(
            { partnerId, fromLuminary: false, read: false },
            { $set: { read: true } }
        );
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Mark read error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update partner status (admin)
app.post('/api/admin/partners/status', requireAdmin, async (req, res) => {
    try {
        const { partnerId, status } = req.body;
        
        if (!['pending', 'viewed', 'responded', 'accepted'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        await db.collection('partners').updateOne(
            { id: partnerId },
            { 
                $set: { 
                    status,
                    lastActivity: new Date().toISOString()
                }
            }
        );
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Update status error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Import partners (admin)
app.post('/api/admin/import', requireAdmin, async (req, res) => {
    try {
        const { partners } = req.body;
        
        if (!Array.isArray(partners)) {
            return res.status(400).json({ error: 'Partners array required' });
        }
        
        // Prepare documents
        const documents = partners.map(p => ({
            ...p,
            status: p.status || 'pending',
            lastActivity: p.lastActivity || new Date().toISOString(),
            createdAt: new Date().toISOString()
        }));
        
        // Insert with ordered: false to continue on duplicates
        let insertedCount = 0;
        
        for (const doc of documents) {
            try {
                await db.collection('partners').insertOne(doc);
                insertedCount++;
            } catch (e) {
                // Skip duplicates (error code 11000)
                if (e.code !== 11000) {
                    console.error('Insert error:', e.message);
                }
            }
        }
        
        res.json({ success: true, insertedCount });
        
    } catch (error) {
        console.error('Import error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get templates (admin)
app.get('/api/admin/templates', requireAdmin, async (req, res) => {
    try {
        const templates = await db.collection('templates').find({}).toArray();
        
        // Convert to object keyed by type
        const result = {};
        templates.forEach(t => {
            result[t.type] = t.content;
        });
        
        res.json(result);
        
    } catch (error) {
        console.error('Get templates error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Save template (admin)
app.post('/api/admin/templates', requireAdmin, async (req, res) => {
    try {
        const { type, content } = req.body;
        
        await db.collection('templates').updateOne(
            { type },
            { 
                $set: { 
                    type,
                    content,
                    updatedAt: new Date().toISOString()
                }
            },
            { upsert: true }
        );
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Save template error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Stats endpoint (admin)
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
    try {
        const totalPartners = await db.collection('partners').countDocuments();
        const universities = await db.collection('partners').countDocuments({ recipientType: 'university' });
        const media = await db.collection('partners').countDocuments({ recipientType: 'media' });
        const pending = await db.collection('partners').countDocuments({ status: 'pending' });
        const responded = await db.collection('partners').countDocuments({ status: 'responded' });
        const accepted = await db.collection('partners').countDocuments({ status: 'accepted' });
        const unreadMessages = await db.collection('messages').countDocuments({ fromLuminary: false, read: false });
        const totalMessages = await db.collection('messages').countDocuments();
        
        res.json({
            totalPartners,
            universities,
            media,
            pending,
            responded,
            accepted,
            unreadMessages,
            totalMessages
        });
        
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== START SERVER =====

async function start() {
    try {
        await connectDB();
        
        app.listen(PORT, () => {
            console.log(`\n✓ Luminary API running on port ${PORT}`);
            console.log(`  Health: http://localhost:${PORT}/api/health\n`);
        });
        
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\nShutting down...');
    if (client) await client.close();
    process.exit(0);
});

start();
