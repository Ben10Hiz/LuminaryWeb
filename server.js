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
    },
    // Resend Configuration
    resendApiKey: process.env.RESEND_API_KEY || '',
    senderEmail: process.env.SENDER_EMAIL || 'media@luminary-tech.ai',
    senderName: process.env.SENDER_NAME || 'Luminary AI Technologies',
    // Perplexity Configuration - trim to handle any whitespace/newline issues
    perplexityApiKey: (process.env.PERPLEXITY_API_KEY || '').trim().split(' ')[0].split('\n')[0] || '',
    // Anthropic (Claude) Configuration
    anthropicApiKey: process.env.ANTHROPIC_API_KEY || ''
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

// CORS Configuration - Allow requests from Luminary domains
const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (mobile apps, curl, etc.)
        if (!origin) return callback(null, true);
        
        // List of allowed origins
        const allowedOrigins = [
            'https://luminary-tech.ai',
            'https://www.luminary-tech.ai',
            'http://localhost:3000',
            'http://localhost:8080',
            'http://127.0.0.1:3000',
            'http://127.0.0.1:8080'
        ];
        
        if (allowedOrigins.includes(origin) || origin.endsWith('.luminary-tech.ai')) {
            callback(null, true);
        } else {
            console.log('CORS blocked origin:', origin);
            callback(null, true); // Allow all for now during development
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
    exposedHeaders: ['Content-Length', 'Content-Type'],
    maxAge: 86400 // Cache preflight for 24 hours
};

app.use(cors(corsOptions));

// Handle preflight requests explicitly
app.options('*', cors(corsOptions));

app.use(express.json({ limit: '50mb' })); // Increased for file attachments
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Error handling for body parsing
app.use((err, req, res, next) => {
    if (err.type === 'entity.too.large') {
        console.error('Request body too large:', err);
        return res.status(413).json({ error: 'Request body too large' });
    }
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        console.error('Invalid JSON:', err);
        return res.status(400).json({ error: 'Invalid JSON in request body' });
    }
    next(err);
});

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
        
        // Log messages with attachments for debugging
        console.log(`Validate-key: Found ${messages.length} messages for partner ${key}`);
        messages.forEach((m, i) => {
            const attCount = m.attachments ? m.attachments.length : 0;
            console.log(`  Message ${i}: "${m.content?.substring(0, 30)}...", attachments: ${attCount}`);
            if (attCount > 0) {
                m.attachments.forEach((a, j) => {
                    console.log(`    Attachment ${j}: ${a.name}, url: ${!!a.url}, data: ${!!a.data}`);
                });
            }
        });
        
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
        
        console.log('Dialogue respond received:', {
            key,
            content,
            attachmentsCount: attachments ? attachments.length : 0,
            attachments: attachments ? attachments.map(a => ({ name: a.name, type: a.type, hasUrl: !!a.url, hasData: !!a.data })) : []
        });
        
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
        
        console.log('Saving message with attachments:', message.attachments.length);
        
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
        console.log('Returning message:', { id: message.id, attachmentsCount: message.attachments.length });
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
        
        // Log messages with attachments
        const msgsWithAttachments = messages.filter(m => m.attachments && m.attachments.length > 0);
        console.log(`Admin partners: Found ${messages.length} total messages, ${msgsWithAttachments.length} with attachments`);
        msgsWithAttachments.forEach(m => {
            console.log(`  Message ${m.id}: ${m.attachments.length} attachments`);
        });
        
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
        
        console.log('Admin message received:', {
            partnerId,
            content: content?.substring(0, 50),
            attachmentsCount: attachments ? attachments.length : 0,
            attachments: attachments ? attachments.map(a => ({ name: a.name, hasUrl: !!a.url, hasData: !!a.data })) : []
        });
        
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
        
        console.log('Saving admin message with attachments:', message.attachments.length);
        
        await db.collection('messages').insertOne(message);
        
        // Update partner activity
        await db.collection('partners').updateOne(
            { id: partnerId },
            { $set: { lastActivity: new Date().toISOString() } }
        );
        
        delete message._id;
        console.log('Admin message saved, returning with attachments:', message.attachments.length);
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

// ===== AI DRAFTING WITH PERPLEXITY =====

// Comprehensive Luminary context for AI
const LUMINARY_CONTEXT = `
ABOUT LUMINARY AI TECHNOLOGIES:

Company Overview:
Luminary AI Technologies is building intelligent infrastructure for complex operations. Founded by Ben Hizer, the company spent three years in stealth development, deliberately avoiding institutional funding to maintain complete independence and creative control.

Core Mission: "For the people, not power"
The fundamental philosophy is making sophisticated tools accessible to entrepreneurs, students, and individuals who traditionally lack access to such resources—not just serving institutions, hedge funds, or corporations.

The Four Platforms:

1. BLUE HAVEN (E-Commerce/Marketplace Intelligence)
   - Real-time market analysis and pricing optimization
   - Seller analytics and competitive intelligence
   - Consumer behavior pattern recognition
   - Designed for small sellers competing against large retailers

2. VESTIQ (Wealth/Financial Markets Intelligence)
   - Market intelligence without the institutional price tag
   - Portfolio analysis and risk assessment
   - Pattern recognition across market data
   - Democratizing tools previously only available to hedge funds
   - First public-facing platform launching soon

3. LEGAL INSIGHTS (Policy & Regulatory Intelligence)
   - Making laws and regulations understandable
   - Policy impact analysis
   - Compliance monitoring and alerts
   - Helping citizens understand how policies affect them
   - Supporting informed civic participation

4. LUMINARY STUDIOS (Development Infrastructure)
   - Agent-driven development platform
   - Natural language to code automation
   - Component transpilation and code generation
   - Internal tool powering all other platforms

Company Positioning:
- NOT institutionally funded - zero Silicon Valley or Wall Street money
- Complete independence enables building for users, not investors
- Challenger to legacy systems across finance, legal, government
- Focus on transcending fragmented systems, not just replacing them
- Commitment to never sell, 20+ years of innovation planned

Key Differentiators:
- Direct connection to primary data sources (not dependent on third parties)
- Unified infrastructure across all platforms (shared intelligence)
- Transparency about challenges and development
- Exploring dispersed ownership models
- Using own Legal Insights platform for compliance

Founder - Ben Hizer:
- 34 years old, based in Indianapolis
- Three years of isolated study and development
- Self-funded through personal sacrifice
- No traditional institutional backing
- Preparing to transition from stealth to public figure
- Vision spans healthcare, education, government reform

Current Phase:
- Preparing for public launch of initial platforms
- Building university and media partnerships
- Vestiq as first public product
- Phase 1 of broader infrastructure strategy

Tone & Voice:
- Professional but accessible
- Confident without arrogance
- Mission-driven authenticity
- "Outsider" positioning against establishment
- Emphasis on empowerment over dependence
`;

// Generate AI draft using Perplexity
app.post('/api/admin/ai/draft', requireAdmin, async (req, res) => {
    try {
        const { type, partner } = req.body;
        
        console.log('AI Draft Request received:', { type, partnerName: partner?.name, partnerOrg: partner?.organization });
        
        if (!partner) {
            return res.status(400).json({ error: 'Partner information required' });
        }
        
        const db = client.db(config.dbName);
        
        // Get full conversation history for this partner
        let fullHistory = [];
        if (partner.id) {
            try {
                // Only convert to ObjectId if it looks like a valid ObjectId
                let query = { id: partner.id };
                if (partner.id.match(/^[0-9a-fA-F]{24}$/)) {
                    query = { 
                        $or: [
                            { _id: new ObjectId(partner.id) },
                            { id: partner.id }
                        ]
                    };
                }
                const partnerDoc = await db.collection('partners').findOne(query);
                if (partnerDoc && partnerDoc.messages) {
                    fullHistory = partnerDoc.messages;
                }
                console.log('Fetched partner history:', fullHistory.length, 'messages');
            } catch (e) {
                console.log('Could not fetch full history:', e.message);
            }
        }
        
        // Build comprehensive partner context
        let conversationSummary = '';
        try {
            conversationSummary = fullHistory.length > 0 ? `
COMPLETE CONVERSATION HISTORY (${fullHistory.length} messages):
${fullHistory.slice(-10).map((m, i) => `
[${i + 1}] ${m.fromLuminary ? 'LUMINARY' : 'PARTNER'} (${m.date ? new Date(m.date).toLocaleDateString() : 'Unknown date'}):
${(m.content || '').substring(0, 500)}
${m.attachments?.length > 0 ? `   [Attachments: ${m.attachments.map(a => a.name || 'file').join(', ')}]` : ''}
`).join('')}

CONVERSATION ANALYSIS:
- Total exchanges: ${fullHistory.length}
- Partner messages: ${fullHistory.filter(m => !m.fromLuminary).length}
- Luminary messages: ${fullHistory.filter(m => m.fromLuminary).length}
- Last activity: ${fullHistory.length > 0 && fullHistory[fullHistory.length - 1].date ? new Date(fullHistory[fullHistory.length - 1].date).toLocaleDateString() : 'Unknown'}
- Relationship stage: ${partner.status === 'accepted' ? 'Active Partnership' : partner.status === 'responded' ? 'In Discussion' : 'Initial Outreach'}
` : `
NO PREVIOUS CONVERSATION - This is initial outreach.
`;
        } catch (e) {
            console.log('Error building conversation summary:', e.message);
            conversationSummary = 'NO PREVIOUS CONVERSATION - This is initial outreach.';
        }

        const partnerContext = `
PARTNER PROFILE:
================
Name/Contact: ${partner.name || 'Unknown'}
Organization: ${partner.organization || 'Unknown'}
Type: ${partner.type === 'media' ? 'MEDIA OUTLET' : 'UNIVERSITY'}
Category/Beat: ${partner.category || 'General'}
Location: ${partner.location || 'Unknown'}
Current Status: ${partner.status || 'pending'}

${partner.type === 'media' ? `
MEDIA-SPECIFIC CONTEXT:
This is a media contact who could help spread Luminary's story. Consider:
- What angle would resonate with their audience?
- How does Luminary's "outsider" narrative fit their coverage?
- What's newsworthy about our approach?
- Timing around our public launch
` : `
UNIVERSITY-SPECIFIC CONTEXT:
This is a potential academic partner. Consider:
- What programs would benefit from our tools?
- Research collaboration opportunities
- Student career pipeline potential
- Innovation/entrepreneurship alignment
`}
${conversationSummary}
`;

        // Build type-specific prompts
        let systemPrompt = `You are the chief communications strategist for Luminary AI Technologies. You write with the voice of someone who deeply believes in democratizing technology access.

${LUMINARY_CONTEXT}

WRITING PRINCIPLES:
1. Every message must feel personally crafted, never templated
2. Reference specific details about the recipient's organization
3. Connect Luminary's mission to their specific interests/coverage
4. Be confident but not salesy - we're offering genuine value
5. Use concrete examples and specifics, avoid vague claims
6. Match tone to relationship stage (formal for new, warmer for ongoing)
7. Always include a clear, specific call to action
8. Keep the "for the people" mission central but not preachy`;

        let userPrompt = '';
        
        switch (type) {
            case 'pitch':
                userPrompt = `${partnerContext}

TASK: Write a compelling initial outreach message.

${partner.type === 'media' ? `
MEDIA PITCH REQUIREMENTS:
- Open with something specific to THEIR publication/coverage (research them)
- Present Luminary's story as genuinely newsworthy, not just promotional
- Emphasize the "outsider vs establishment" narrative
- Mention the deliberate rejection of institutional funding
- Connect to current trends they cover (AI democratization, fintech disruption, etc.)
- Offer exclusive access or early information
- Suggest a specific format (interview, feature, exclusive, etc.)
- Be respectful of their time - they get hundreds of pitches
` : `
UNIVERSITY PITCH REQUIREMENTS:
- Reference specific programs or initiatives at their institution
- Lead with value TO THEM (student access, research collaboration, career pipeline)
- Position as partnership, not vendor relationship
- Mention relevant platforms (Vestiq for business schools, Legal Insights for law, etc.)
- Offer pilot program or early access
- Emphasize practical, real-world experience for students
- Suggest specific collaboration model
`}

Write 200-300 words. Make it impossible to confuse with a mass email.`;
                break;
                
            case 'followup':
                userPrompt = `${partnerContext}

TASK: Write a follow-up message that advances the relationship.

FOLLOW-UP REQUIREMENTS:
${fullHistory.length > 0 ? `
- Directly reference specific points from previous conversation
- Acknowledge any questions or concerns they raised
- Provide any information they requested
- Show you've been thinking about the partnership
- Add NEW value or information (don't just repeat previous pitch)
- Be appropriately persistent without being pushy
` : `
- Acknowledge the previous outreach naturally
- Offer a new angle or piece of information
- Make responding easy (yes/no question, specific time slots)
- Show continued genuine interest
`}
- Include specific call to action with timeline
- Keep it concise (100-150 words) - respect their inbox

The tone should be ${partner.status === 'responded' ? 'warm and collaborative' : 'professionally persistent'}.`;
                break;
                
            case 'contract':
                userPrompt = `${partnerContext}

TASK: Draft a partnership agreement outline customized for this specific partner.

AGREEMENT REQUIREMENTS:
- Tailor every section to ${partner.organization || 'this organization'}
- Reference their specific context and our conversations
- ${partner.type === 'media' ? `
  Media Partnership sections:
  * Story access and timing agreements
  * Exclusivity windows for major announcements
  * Quote approval and fact-checking process
  * Long-term relationship structure
  * Mutual promotion terms
  ` : `
  University Partnership sections:
  * Platform access scope and terms
  * Student/faculty eligibility
  * Research collaboration framework
  * Data usage and privacy
  * Internship/career pipeline structure
  * Academic credit possibilities
  `}
- Make it feel like a genuine partnership, not a legal document
- Include specific deliverables and timelines
- Leave room for customization
- End with clear next steps

This should read as a thoughtful proposal, not boilerplate.`;
                break;
                
            case 'research':
                systemPrompt = `You are a strategic research analyst preparing background intelligence for business development outreach.

${LUMINARY_CONTEXT}

Your research should be actionable - focused on finding angles and opportunities for partnership, not just facts.`;

                userPrompt = `RESEARCH TARGET: ${partner.organization || partner.name}
Type: ${partner.type === 'media' ? 'Media Outlet' : 'University'}
${partner.category ? `Category/Focus: ${partner.category}` : ''}
${partner.location ? `Location: ${partner.location}` : ''}

RESEARCH OBJECTIVES:
${partner.type === 'media' ? `
FOR MEDIA OUTLET:
1. COVERAGE ANALYSIS
   - What topics do they typically cover?
   - Recent articles about AI, fintech, startups, or tech disruption
   - Their editorial stance and tone
   - Audience demographics and reach

2. KEY PERSONNEL
   - Relevant journalists, editors, or producers
   - Their individual beats and interests
   - Social media presence and engagement style
   - Previous notable interviews or features

3. PITCH ANGLES
   - What Luminary stories would resonate?
   - Timing considerations (news cycles, editorial calendars)
   - Format preferences (features, interviews, op-eds)
   - Competitive coverage to reference or differentiate from

4. RELATIONSHIP INTELLIGENCE
   - Have they covered similar companies?
   - Any connections or warm introduction paths?
   - Red flags or sensitivities to avoid
` : `
FOR UNIVERSITY:
1. ACADEMIC PROGRAMS
   - Relevant departments (CS, Business, Engineering, Law, etc.)
   - Specific courses that align with our platforms
   - Research centers or labs in AI/ML/fintech
   - Student enrollment and program reputation

2. INNOVATION ECOSYSTEM
   - Entrepreneurship programs or incubators
   - Industry partnership models they use
   - Notable startups or alumni in our space
   - Career services and employer relationships

3. KEY CONTACTS
   - Department chairs and program directors
   - Industry relations or partnership offices
   - Faculty with relevant research interests
   - Student organizations (entrepreneurship, tech, finance)

4. PARTNERSHIP OPPORTUNITIES
   - Existing corporate partnership models
   - Guest lecture or workshop possibilities
   - Research collaboration potential
   - Internship program structures
`}

Provide SPECIFIC, ACTIONABLE intelligence. Include URLs and names where possible.
Format with clear sections and bullet points.`;
                break;
                
            default:
                return res.status(400).json({ error: 'Invalid draft type' });
        }
        
        // Call Perplexity API
        if (!config.perplexityApiKey) {
            return res.json({
                content: generateFallbackDraft(type, partner, fullHistory)
            });
        }
        
        console.log(`AI Draft Request: ${type} for ${partner.organization || partner.name}`);
        
        // Call Perplexity API
        let finalContent = '';
        
        try {
            console.log('Calling Perplexity API...');
            
            const perplexityResponse = await fetch('https://api.perplexity.ai/chat/completions', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${config.perplexityApiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: 'sonar',
                    messages: [
                        { role: 'system', content: systemPrompt },
                        { role: 'user', content: userPrompt }
                    ],
                    temperature: 0.7,
                    max_tokens: 2500,
                    return_citations: true,
                    search_recency_filter: 'month'
                })
            });
            
            const perplexityResult = await perplexityResponse.json();
            
            if (!perplexityResponse.ok) {
                console.error('Perplexity API error:', perplexityResult);
                finalContent = generateFallbackDraft(type, partner, fullHistory);
            } else {
                const content = perplexityResult.choices?.[0]?.message?.content;
                const citations = perplexityResult.citations || [];
                
                if (!content) {
                    console.log('No content in Perplexity response, using fallback');
                    finalContent = generateFallbackDraft(type, partner, fullHistory);
                } else {
                    console.log(`AI Draft Generated: ${type} for ${partner.organization || partner.name} (${content.length} chars)`);
                    
                    finalContent = content;
                    if (type === 'research' && citations.length > 0) {
                        finalContent += `\n\n---\nSOURCES:\n${citations.map((c, i) => `[${i + 1}] ${c}`).join('\n')}`;
                    }
                }
            }
        } catch (perplexityError) {
            console.error('Perplexity API call failed:', perplexityError.message);
            finalContent = generateFallbackDraft(type, partner, fullHistory);
        }
        
        res.json({ content: finalContent });
        
    } catch (error) {
        console.error('AI draft error:', error.message, error.stack);
        res.status(500).json({ error: 'Failed to generate draft: ' + error.message });
    }
});

// Simple research query via Perplexity
app.post('/api/admin/ai/research', requireAdmin, async (req, res) => {
    try {
        const { query, partner } = req.body;
        
        if (!query) {
            return res.status(400).json({ error: 'Query required' });
        }
        
        console.log('Research query:', query.substring(0, 100) + '...');
        
        // Check if Perplexity API key exists and is valid
        const apiKey = config.perplexityApiKey;
        if (!apiKey || !apiKey.startsWith('pplx-')) {
            console.log('Invalid or missing Perplexity API key');
            return res.json({ 
                content: `Research query received for ${partner?.organization || 'organization'}. Perplexity API key not properly configured. Please ensure PERPLEXITY_API_KEY environment variable is set correctly (should start with 'pplx-').`
            });
        }
        
        try {
            const perplexityResponse = await fetch('https://api.perplexity.ai/chat/completions', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: 'sonar',
                    messages: [
                        { 
                            role: 'system', 
                            content: 'You are a business intelligence researcher. Provide factual, well-organized information. Be concise but comprehensive. Include specific names, numbers, and dates when available.'
                        },
                        { role: 'user', content: query }
                    ],
                    temperature: 0.3,
                    max_tokens: 1500
                })
            });
            
            const result = await perplexityResponse.json();
            
            if (!perplexityResponse.ok) {
                console.error('Perplexity API error:', result);
                // Return a helpful message instead of failing
                return res.json({ 
                    content: `Research request processed. The AI service returned an error: ${result.error?.message || 'Unknown error'}. Please try again or contact support.`
                });
            }
            
            const content = result.choices?.[0]?.message?.content || 'No results found.';
            
            res.json({ content });
            
        } catch (perplexityError) {
            console.error('Perplexity fetch error:', perplexityError.message);
            return res.json({ 
                content: `Research service temporarily unavailable. Error: ${perplexityError.message}. Please try again in a moment.`
            });
        }
        
    } catch (error) {
        console.error('Research error:', error.message, error.stack);
        res.status(500).json({ error: 'Research failed: ' + error.message });
    }
});

// Generate proposal via Claude API
app.post('/api/admin/ai/proposal', requireAdmin, async (req, res) => {
    try {
        const { partner, research, config: proposalConfig } = req.body;
        
        if (!partner || !proposalConfig) {
            return res.status(400).json({ error: 'Partner and config required' });
        }
        
        console.log('Generating proposal for:', partner.organization || partner.name);
        
        // Check if Anthropic API key is available
        if (!config.anthropicApiKey) {
            console.log('No Anthropic API key, using fallback');
            return generateProposalFallback(res, partner, research, proposalConfig);
        }
        
        // Build research summary
        const researchSummary = Object.entries(research || {})
            .map(([key, value]) => `### ${key.replace(/_/g, ' ').toUpperCase()}\n${value}`)
            .join('\n\n');
        
        const platformNames = {
            vestiq: 'Vestiq (Financial Markets Intelligence)',
            bluehaven: 'Blue Haven (E-Commerce & Marketplace Intelligence)',
            legalinsights: 'Legal Insights (Policy & Regulatory Intelligence)',
            all: 'Full Platform Suite (Vestiq, Blue Haven, Legal Insights)'
        };
        
        const tierDescriptions = {
            explorer: 'Explorer tier provides foundational access for organizations beginning their AI intelligence journey.',
            partner: 'Partner tier offers comprehensive access with dedicated support and integration capabilities.',
            enterprise: 'Enterprise tier delivers full platform capabilities with custom integrations, priority support, and strategic advisory.'
        };
        
        // Detect if partner has Bloomberg or similar high-cost tools
        const techResearch = research?.tech_contracts?.content || '';
        const hasBloomberg = techResearch.toLowerCase().includes('bloomberg');
        const bloombergComparison = hasBloomberg ? 
            `Based on research, ${partner.organization || partner.name} maintains Bloomberg terminals (~$25,000/year each, serving ~5-10 students at a time). Our platform provides equivalent analytical capabilities to every student on their own device for a single flat fee.` : '';
        
        // Calculate per-student cost if seats provided
        const perStudentCost = proposalConfig.seats > 0 ? (proposalConfig.amount / proposalConfig.seats).toFixed(2) : null;
        
        // Legacy Fund calculations (10% contribution, 8% growth, 4% distribution)
        const legacyFundEnabled = proposalConfig.legacyFund?.enabled || false;
        const legacyContribution = legacyFundEnabled ? Math.round(proposalConfig.amount * 0.10) : 0;
        
        const systemPrompt = `You are a senior business development professional at Luminary AI Technologies. You write compelling, professional partnership proposals that are TRANSPARENT and LOGICAL, not salesy.

${LUMINARY_CONTEXT}

CRITICAL PROPOSAL PHILOSOPHY:
1. This is NOT a sales pitch - it's an invitation to join a 100-year infrastructure
2. Be radically transparent about pricing logic ("Our Logic" sections)
3. Frame as "University Access License" or "Institutional Access" - not per-seat software
4. Reference their specific research, budget realities, and comparable tool costs
5. We are "for the people, not power" - emphasize accessibility and long-term value
6. Include concrete comparisons (e.g., Bloomberg terminal costs)
7. Make approval easy by suggesting the right budget bucket

TONE: Authoritative, visionary, transparent. We are building something important and inviting them to be part of it.

FORMAT: Use markdown with clear sections. Be comprehensive but never verbose.`;

        const userPrompt = `Create a partnership proposal for:

PARTNER: ${partner.organization || partner.name}
TYPE: ${partner.type === 'media' ? 'Media Partnership' : 'Academic/Institutional Partnership'}
LOCATION: ${partner.location || 'Not specified'}

RESEARCH GATHERED:
${researchSummary || 'No specific research available.'}

PROPOSED TERMS:
- Tier: ${proposalConfig.tier} (${tierDescriptions[proposalConfig.tier]})
- Investment: $${proposalConfig.amount.toLocaleString()} annually (flat institutional fee)
- Term: ${proposalConfig.term} months with Founding Partner rate lock
- Payment Schedule: ${proposalConfig.paymentSchedule || 'annual upfront'}
- Platform: ${platformNames[proposalConfig.platform]}
- Access: ${proposalConfig.seats === 999 ? 'Unlimited institutional access' : proposalConfig.seats + ' user seats'}
${perStudentCost ? `- Per-Student Equivalent: ~$${perStudentCost} (less than a textbook)` : ''}
${proposalConfig.deliverables ? `- Deliverables:\n${proposalConfig.deliverables.split('\n').map(d => '  • ' + d).join('\n')}` : ''}

${bloombergComparison ? `BLOOMBERG COMPARISON:\n${bloombergComparison}` : ''}

INVESTMENT RATIONALE (from our analysis):
${proposalConfig.rationale || 'Standard value proposition based on platform capabilities.'}

PAYMENT PATHWAY (suggested funding approach):
${proposalConfig.paymentPathway || 'Standard institutional procurement process.'}

${legacyFundEnabled ? `LEGACY FUND ENABLED:
- Annual Contribution: $${legacyContribution} (10% of fee)
- Vesting Period: 3 years
- Distribution: 4% annually after vesting
- Contingent on Luminary's financial health` : ''}

Generate a complete partnership proposal with these EXACT sections in this order:

## 1. THE VISION & GOAL
Introduce ${partner.organization || partner.name} to Luminary's 100-year infrastructure vision. We are not merely providing software; we are establishing a new standard. Invite them to join as a Founding Partner. (2-3 paragraphs)

## 2. THE PROPOSAL: UNIVERSITY ACCESS LICENSE
Describe the flat institutional access being offered. Emphasize:
- All students and faculty can create accounts
- Platform is designed for lifelong value
- Access includes research publications and evolving strategies
(3-4 paragraphs)

## 3. THE COST & RATIONALE
State the single flat annual fee: $${proposalConfig.amount.toLocaleString()}

Then include a sub-section titled "### OUR LOGIC: How We Arrived at This Figure"
Be radically transparent. Include:
- Comparison to comparable tools (Bloomberg if relevant)
- Per-student value calculation
- Which budget bucket this fits (Instructional Materials = easy, IT = hard)
- Infrastructure & Longevity justification

Then list "### What This Covers" (bulleted list of inclusions)
And "### What This Does NOT Cover" (bulleted list of exclusions/add-ons)

${legacyFundEnabled ? `## 4. THE LEGACY FUND
Describe the perpetual fund we establish for Founding Partners:
- $${legacyContribution} annual contribution (10% of fee)
- 3-year vesting, then 4% annual distributions
- Show projected growth table for years 1, 3, 5, 10, 20
- Note contingency on financial health
` : ''}

## ${legacyFundEnabled ? '5' : '4'}. PARTNERSHIP EXPECTATIONS
What we ask in return (non-binding):
- Marketing rights (logo as "Research Partner")
- Feedback loop (30-min call per semester)
- Optional: case study participation, recruiting access

## ${legacyFundEnabled ? '6' : '5'}. NEXT STEPS
Clear action items:
- Timeline for discussion and execution
- Founding Partner rate lock guarantee
- Implementation timeline

## SIGNATURE BLOCK
Placeholders for both Luminary AI Technologies and ${partner.organization || partner.name}

Make this specific to ${partner.organization || partner.name}. Use their name throughout, reference their specific situation from the research. Be transparent about our logic, not salesy.`;

        // Call Claude API via Anthropic
        const claudeResponse = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'x-api-key': config.anthropicApiKey,
                'anthropic-version': '2023-06-01',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: 'claude-sonnet-4-20250514',
                max_tokens: 4000,
                system: systemPrompt,
                messages: [
                    { role: 'user', content: userPrompt }
                ]
            })
        });
        
        const claudeResult = await claudeResponse.json();
        
        if (!claudeResponse.ok) {
            console.error('Claude API error:', claudeResult);
            // Fallback to Perplexity for proposal generation
            return generateProposalFallback(res, partner, research, proposalConfig);
        }
        
        const proposal = claudeResult.content?.[0]?.text || '';
        
        if (!proposal) {
            return generateProposalFallback(res, partner, research, proposalConfig);
        }
        
        // Convert markdown to basic HTML for preview
        let proposalHtml = proposal
            .replace(/^### (.+)$/gm, '<h3>$1</h3>')
            .replace(/^## (.+)$/gm, '<h2>$1</h2>')
            .replace(/^# (.+)$/gm, '<h1>$1</h1>')
            .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
            .replace(/^\- (.+)$/gm, '<li>$1</li>')
            .replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>')
            .replace(/\n\n/g, '</p><p>')
            .replace(/\n/g, '<br>');
        proposalHtml = '<p>' + proposalHtml + '</p>';
        
        console.log('Proposal generated successfully');
        
        res.json({ 
            proposal, 
            proposalHtml: `
                <div class="proposal-header">
                    <div class="proposal-logo">LUMINARY</div>
                    <p style="margin-top: 0.5rem; color: #666;">Partnership Proposal</p>
                </div>
                ${proposalHtml}
            `
        });
        
    } catch (error) {
        console.error('Proposal generation error:', error);
        res.status(500).json({ error: 'Failed to generate proposal' });
    }
});

// Fallback proposal generator
async function generateProposalFallback(res, partner, research, proposalConfig) {
    const orgName = partner.organization || partner.name;
    const proposal = `# PARTNERSHIP PROPOSAL

## ${orgName} & Luminary AI Technologies

**Prepared:** ${new Date().toLocaleDateString()}

---

## EXECUTIVE SUMMARY

Luminary AI Technologies proposes a strategic partnership with ${orgName} to provide access to our AI-powered intelligence platforms, enabling data-driven decision making and operational excellence.

## ABOUT LUMINARY AI TECHNOLOGIES

Luminary AI Technologies builds intelligent infrastructure for complex operations. Our mission is "for the people, not power" - making sophisticated tools accessible to organizations of all sizes.

**Our Platforms:**
- **Vestiq** - Financial markets intelligence
- **Blue Haven** - E-commerce and marketplace analytics
- **Legal Insights** - Policy and regulatory intelligence

## PARTNERSHIP OVERVIEW

This ${proposalConfig.term}-month partnership provides ${orgName} with:
- Full platform access for ${proposalConfig.seats} users
- Dedicated onboarding and training
- Priority technical support
- Quarterly business reviews

## INVESTMENT & TERMS

**Annual Investment:** $${proposalConfig.amount.toLocaleString()}
**Term:** ${proposalConfig.term} months
**Payment:** Annual or quarterly options available

## INVESTMENT RATIONALE

${proposalConfig.rationale || `The proposed investment of $${proposalConfig.amount.toLocaleString()} annually positions ${orgName} to leverage enterprise-grade AI intelligence at a fraction of traditional costs. Based on similar partnerships, organizations typically see 3-5x ROI through improved decision-making efficiency and competitive intelligence.`}

## NEXT STEPS

1. Review this proposal
2. Schedule partnership discussion call
3. Customize terms as needed
4. Execute agreement
5. Begin onboarding

---

## SIGNATURES

**For Luminary AI Technologies:**

_______________________________
Ben Hizer, Founder
Date: _______________

**For ${orgName}:**

_______________________________
Name: _______________
Title: _______________
Date: _______________
`;
    
    res.json({ 
        proposal,
        proposalHtml: proposal
            .replace(/^### (.+)$/gm, '<h3>$1</h3>')
            .replace(/^## (.+)$/gm, '<h2>$1</h2>')
            .replace(/^# (.+)$/gm, '<h1>$1</h1>')
            .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
            .replace(/\n\n/g, '</p><p>')
    });
}

// Download proposal as DOCX
app.post('/api/admin/ai/proposal/download', requireAdmin, async (req, res) => {
    try {
        const { proposal, partner, config: proposalConfig } = req.body;
        
        if (!proposal) {
            return res.status(400).json({ error: 'Proposal content required' });
        }
        
        // For now, return the proposal as a simple text file
        // In production, this would use docx-js to create a proper Word document
        
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
        res.setHeader('Content-Disposition', `attachment; filename="Luminary_Proposal_${(partner?.organization || 'Partner').replace(/\s+/g, '_')}.docx"`);
        
        // Simple RTF conversion for now (Word can open this)
        const rtfContent = `{\\rtf1\\ansi\\deff0
{\\fonttbl{\\f0 Arial;}{\\f1 Georgia;}}
{\\colortbl;\\red212\\green168\\blue83;\\red26\\green26\\blue26;}
\\f0\\fs24
${proposal.replace(/\n/g, '\\par ')}
}`;
        
        res.send(rtfContent);
        
    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({ error: 'Failed to generate document' });
    }
});

// ===== RESEARCH STORAGE ENDPOINTS =====

// Generate Investment Rationale
app.post('/api/admin/ai/generate-rationale', requireAdmin, async (req, res) => {
    try {
        const { partner, terms, research } = req.body;
        
        console.log('Generating investment rationale for:', partner.organization);
        
        const researchSummary = Object.entries(research || {})
            .filter(([key, value]) => value && value.content)
            .map(([key, value]) => `${key}: ${value.content.substring(0, 500)}`)
            .join('\n\n');
        
        const prompt = `You are writing an investment rationale for a partnership proposal from Luminary AI Technologies.

PARTNER: ${partner.organization || partner.name}
TYPE: ${partner.type === 'media' ? 'Media Partnership' : 'University/Institutional Partnership'}

PROPOSED TERMS:
- Annual Investment: $${terms.amount.toLocaleString()}
- Platform: ${terms.platform}
- User Seats: ${terms.seats}
- Term: ${terms.term} months
- Tier: ${terms.tier}

AVAILABLE RESEARCH:
${researchSummary || 'Limited research available.'}

Write a clear, logical investment rationale that explains:
1. SCOPE OF ACCESS - What the partner gets for this investment
2. VALUE DELIVERED - Specific outcomes and capabilities
3. INVESTMENT LOGIC - How the amount was determined, what's included

Keep it professional, transparent, and focused on facts. Do NOT oversell or make exaggerated claims.
Format with clear sections. Keep it under 400 words.`;

        const perplexityResponse = await fetch('https://api.perplexity.ai/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${config.perplexityApiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: 'sonar',
                messages: [
                    { role: 'user', content: prompt }
                ],
                temperature: 0.5,
                max_tokens: 1000
            })
        });
        
        const result = await perplexityResponse.json();
        const rationale = result.choices?.[0]?.message?.content || '';
        
        res.json({ rationale });
        
    } catch (error) {
        console.error('Generate rationale error:', error);
        res.status(500).json({ error: 'Failed to generate rationale' });
    }
});

// Generate Payment Pathway
app.post('/api/admin/ai/generate-pathway', requireAdmin, async (req, res) => {
    try {
        const { partner, research, amount } = req.body;
        
        console.log('Generating payment pathway for:', partner.organization);
        
        // Extract relevant research sections
        const budgetResearch = research?.budget_cycles?.content || '';
        const paymentResearch = research?.payment_pathway?.content || '';
        const partnershipRules = research?.vendor_rules?.content || '';
        const taxBenefits = research?.tax_benefits?.content || '';
        
        const prompt = `Based on the following research, create a payment pathway analysis for ${partner.organization} to fund a $${amount.toLocaleString()} annual partnership with Luminary AI Technologies.

BUDGET & FUNDING RESEARCH:
${budgetResearch || 'No specific budget research available.'}

PAYMENT PATHWAY RESEARCH:
${paymentResearch || 'No specific payment pathway research available.'}

PARTNERSHIP REQUIREMENTS:
${partnershipRules || 'No specific partnership rules research available.'}

TAX BENEFITS RESEARCH:
${taxBenefits || 'No specific tax benefits research available.'}

Create a clear payment pathway analysis that includes:

1. FUNDING SOURCE
   - Most likely budget or fund to cover this investment
   - Grant opportunities if applicable
   - Department or cost center

2. APPROVAL PROCESS
   - Key decision makers who would need to approve
   - Typical timeline for approval
   - Required documentation

3. TIMING CONSIDERATIONS
   - Their fiscal year calendar
   - Optimal timing for submitting proposal
   - Budget cycle deadlines

4. TAX & INCENTIVE BENEFITS
   - Any available tax credits or deductions
   - Educational or R&D incentives
   - State-specific programs

Be specific where research supports it. Where research is limited, note that additional discovery may be needed. Keep under 400 words.`;

        const perplexityResponse = await fetch('https://api.perplexity.ai/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${config.perplexityApiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: 'sonar',
                messages: [
                    { role: 'user', content: prompt }
                ],
                temperature: 0.5,
                max_tokens: 1000
            })
        });
        
        const result = await perplexityResponse.json();
        const pathway = result.choices?.[0]?.message?.content || '';
        
        res.json({ pathway });
        
    } catch (error) {
        console.error('Generate pathway error:', error);
        res.status(500).json({ error: 'Failed to generate payment pathway' });
    }
});

// Get research for a partner
app.get('/api/admin/partners/:id/research', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        const partnerId = req.params.id;
        
        let query = { id: partnerId };
        if (partnerId.match(/^[0-9a-fA-F]{24}$/)) {
            query = { 
                $or: [
                    { _id: new ObjectId(partnerId) },
                    { id: partnerId }
                ]
            };
        }
        
        const partner = await db.collection('partners').findOne(query);
        
        if (!partner) {
            return res.status(404).json({ error: 'Partner not found' });
        }
        
        res.json({ 
            research: partner.research || {},
            lastUpdated: partner.researchLastUpdated || null
        });
        
    } catch (error) {
        console.error('Get research error:', error);
        res.status(500).json({ error: 'Failed to get research' });
    }
});

// Save research for a partner
app.put('/api/admin/partners/:id/research', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        const partnerId = req.params.id;
        const { research } = req.body;
        
        if (!research) {
            return res.status(400).json({ error: 'Research data required' });
        }
        
        let query = { id: partnerId };
        if (partnerId.match(/^[0-9a-fA-F]{24}$/)) {
            query = { 
                $or: [
                    { _id: new ObjectId(partnerId) },
                    { id: partnerId }
                ]
            };
        }
        
        const result = await db.collection('partners').updateOne(
            query,
            { 
                $set: { 
                    research: research,
                    researchLastUpdated: new Date().toISOString()
                }
            }
        );
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Partner not found' });
        }
        
        console.log(`Research saved for partner ${partnerId}: ${Object.keys(research).length} categories`);
        
        res.json({ 
            success: true, 
            categoriesStored: Object.keys(research).length 
        });
        
    } catch (error) {
        console.error('Save research error:', error);
        res.status(500).json({ error: 'Failed to save research' });
    }
});

// Get research summary for all partners (for dashboard)
app.get('/api/admin/research/summary', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        
        const partners = await db.collection('partners')
            .find({ research: { $exists: true, $ne: {} } })
            .project({ 
                _id: 1, 
                recipientName: 1, 
                organizationName: 1, 
                universityName: 1,
                research: 1,
                researchLastUpdated: 1
            })
            .toArray();
        
        const summary = partners.map(p => ({
            id: p._id,
            name: p.organizationName || p.universityName || p.recipientName,
            categoriesCompleted: Object.keys(p.research || {}).filter(k => p.research[k]?.content).length,
            lastUpdated: p.researchLastUpdated
        }));
        
        res.json({ partners: summary });
        
    } catch (error) {
        console.error('Research summary error:', error);
        res.status(500).json({ error: 'Failed to get research summary' });
    }
});

// ===== PROPOSAL STORAGE WITH SIDENOTES =====

// Get proposal for a partner
app.get('/api/admin/partners/:id/proposal', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        const partnerId = req.params.id;
        
        let query = { id: partnerId };
        if (partnerId.match(/^[0-9a-fA-F]{24}$/)) {
            query = { 
                $or: [
                    { _id: new ObjectId(partnerId) },
                    { id: partnerId }
                ]
            };
        }
        
        const partner = await db.collection('partners').findOne(query);
        
        if (!partner) {
            return res.status(404).json({ error: 'Partner not found' });
        }
        
        res.json({ 
            proposal: partner.proposal || null
        });
        
    } catch (error) {
        console.error('Get proposal error:', error);
        res.status(500).json({ error: 'Failed to get proposal' });
    }
});

// Save proposal for a partner
app.put('/api/admin/partners/:id/proposal', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        const partnerId = req.params.id;
        const { content, status, sidenotes, signatures, config: proposalConfig } = req.body;
        
        let query = { id: partnerId };
        if (partnerId.match(/^[0-9a-fA-F]{24}$/)) {
            query = { 
                $or: [
                    { _id: new ObjectId(partnerId) },
                    { id: partnerId }
                ]
            };
        }
        
        const proposal = {
            content: content || '',
            status: status || 'draft',
            sidenotes: sidenotes || [],
            signatures: signatures || { luminary: null, partner: null },
            config: proposalConfig || {},
            updatedAt: new Date().toISOString()
        };
        
        // Check if this is a new proposal
        const existing = await db.collection('partners').findOne(query);
        if (existing && !existing.proposal?.createdAt) {
            proposal.createdAt = new Date().toISOString();
        } else if (existing?.proposal?.createdAt) {
            proposal.createdAt = existing.proposal.createdAt;
        } else {
            proposal.createdAt = new Date().toISOString();
        }
        
        // Track execution timestamp
        if (status === 'executed' && signatures?.luminary?.signed && signatures?.partner?.signed) {
            proposal.executedAt = new Date().toISOString();
        }
        
        const result = await db.collection('partners').updateOne(
            query,
            { 
                $set: { 
                    proposal: proposal
                }
            }
        );
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Partner not found' });
        }
        
        console.log(`Proposal saved for partner ${partnerId}: status=${status}, sidenotes=${sidenotes?.length || 0}, signatures=${Object.keys(signatures || {}).filter(k => signatures[k]?.signed).length}/2`);
        
        res.json({ 
            success: true,
            status: status,
            sidenotesCount: sidenotes?.length || 0,
            signaturesComplete: signatures?.luminary?.signed && signatures?.partner?.signed
        });
        
    } catch (error) {
        console.error('Save proposal error:', error);
        res.status(500).json({ error: 'Failed to save proposal' });
    }
});

// Add sidenote to proposal
app.post('/api/admin/partners/:id/proposal/sidenote', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        const partnerId = req.params.id;
        const { author, authorType, content, section } = req.body;
        
        if (!content) {
            return res.status(400).json({ error: 'Content required' });
        }
        
        let query = { id: partnerId };
        if (partnerId.match(/^[0-9a-fA-F]{24}$/)) {
            query = { 
                $or: [
                    { _id: new ObjectId(partnerId) },
                    { id: partnerId }
                ]
            };
        }
        
        const newSidenote = {
            id: 'note_' + Date.now(),
            author: author || 'Luminary',
            authorType: authorType || 'luminary',
            content: content,
            section: section || null,
            timestamp: new Date().toISOString(),
            resolved: false
        };
        
        const result = await db.collection('partners').updateOne(
            query,
            { 
                $push: { 'proposal.sidenotes': newSidenote },
                $set: { 'proposal.updatedAt': new Date().toISOString() }
            }
        );
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Partner not found' });
        }
        
        res.json({ 
            success: true,
            sidenote: newSidenote
        });
        
    } catch (error) {
        console.error('Add sidenote error:', error);
        res.status(500).json({ error: 'Failed to add sidenote' });
    }
});

// Update proposal status
app.patch('/api/admin/partners/:id/proposal/status', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        const partnerId = req.params.id;
        const { status } = req.body;
        
        const validStatuses = ['draft', 'review', 'pending-signature', 'executed'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        let query = { id: partnerId };
        if (partnerId.match(/^[0-9a-fA-F]{24}$/)) {
            query = { 
                $or: [
                    { _id: new ObjectId(partnerId) },
                    { id: partnerId }
                ]
            };
        }
        
        const updateData = {
            'proposal.status': status,
            'proposal.updatedAt': new Date().toISOString()
        };
        
        // Add status change timestamp
        if (status === 'executed') {
            updateData['proposal.executedAt'] = new Date().toISOString();
        }
        
        const result = await db.collection('partners').updateOne(
            query,
            { $set: updateData }
        );
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Partner not found' });
        }
        
        console.log(`Proposal status updated for partner ${partnerId}: ${status}`);
        
        res.json({ success: true, status });
        
    } catch (error) {
        console.error('Update proposal status error:', error);
        res.status(500).json({ error: 'Failed to update status' });
    }
});

// ===== RESEARCH STORAGE ENDPOINTS =====

// Get research data for a partner
app.get('/api/admin/partners/:id/research', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        const partnerId = req.params.id;
        
        let query = { id: partnerId };
        if (partnerId.match(/^[0-9a-fA-F]{24}$/)) {
            query = { 
                $or: [
                    { _id: new ObjectId(partnerId) },
                    { id: partnerId }
                ]
            };
        }
        
        const partner = await db.collection('partners').findOne(query);
        
        if (!partner) {
            return res.status(404).json({ error: 'Partner not found' });
        }
        
        res.json({ research: partner.research || {} });
        
    } catch (error) {
        console.error('Get research error:', error);
        res.status(500).json({ error: 'Failed to get research' });
    }
});

// Save research data for a partner
app.put('/api/admin/partners/:id/research', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        const partnerId = req.params.id;
        const { research } = req.body;
        
        let query = { id: partnerId };
        if (partnerId.match(/^[0-9a-fA-F]{24}$/)) {
            query = { 
                $or: [
                    { _id: new ObjectId(partnerId) },
                    { id: partnerId }
                ]
            };
        }
        
        await db.collection('partners').updateOne(
            query,
            { 
                $set: { 
                    research,
                    researchUpdatedAt: new Date()
                } 
            }
        );
        
        console.log('Research saved for partner:', partnerId);
        res.json({ success: true });
        
    } catch (error) {
        console.error('Save research error:', error);
        res.status(500).json({ error: 'Failed to save research' });
    }
});

// ===== PROPOSAL ENDPOINTS =====

// Get proposal for a partner
app.get('/api/admin/proposals/:partnerId', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        const partnerId = req.params.partnerId;
        
        const proposal = await db.collection('proposals').findOne({ partnerId });
        
        res.json({ proposal: proposal || null });
        
    } catch (error) {
        console.error('Get proposal error:', error);
        res.status(500).json({ error: 'Failed to get proposal' });
    }
});

// Save/update proposal
app.put('/api/admin/proposals/:partnerId', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        const partnerId = req.params.partnerId;
        const { content, config: proposalConfig, status } = req.body;
        
        await db.collection('proposals').updateOne(
            { partnerId },
            { 
                $set: { 
                    partnerId,
                    content,
                    config: proposalConfig,
                    status: status || 'draft',
                    updatedAt: new Date()
                },
                $setOnInsert: {
                    createdAt: new Date()
                }
            },
            { upsert: true }
        );
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Save proposal error:', error);
        res.status(500).json({ error: 'Failed to save proposal' });
    }
});

// Save signature
app.post('/api/admin/proposals/:partnerId/signature', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        const partnerId = req.params.partnerId;
        const { party, signature } = req.body;
        
        const updateField = party === 'luminary' ? 'signatures.luminary' : 'signatures.partner';
        
        await db.collection('proposals').updateOne(
            { partnerId },
            { 
                $set: { 
                    [updateField]: signature,
                    updatedAt: new Date()
                }
            },
            { upsert: true }
        );
        
        // Check if both signatures are present
        const proposal = await db.collection('proposals').findOne({ partnerId });
        if (proposal?.signatures?.luminary && proposal?.signatures?.partner) {
            await db.collection('proposals').updateOne(
                { partnerId },
                { $set: { status: 'executed', executedAt: new Date() } }
            );
        }
        
        console.log(`Signature saved for ${party} on proposal ${partnerId}`);
        res.json({ success: true });
        
    } catch (error) {
        console.error('Save signature error:', error);
        res.status(500).json({ error: 'Failed to save signature' });
    }
});

// ===== SIDENOTES ENDPOINTS =====

// Get sidenotes for a proposal
app.get('/api/admin/proposals/:partnerId/sidenotes', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        const partnerId = req.params.partnerId;
        
        const proposal = await db.collection('proposals').findOne({ partnerId });
        
        res.json({ sidenotes: proposal?.sidenotes || [] });
        
    } catch (error) {
        console.error('Get sidenotes error:', error);
        res.status(500).json({ error: 'Failed to get sidenotes' });
    }
});

// Save sidenotes
app.put('/api/admin/proposals/:partnerId/sidenotes', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        const partnerId = req.params.partnerId;
        const { sidenotes } = req.body;
        
        await db.collection('proposals').updateOne(
            { partnerId },
            { 
                $set: { 
                    sidenotes,
                    updatedAt: new Date()
                }
            },
            { upsert: true }
        );
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Save sidenotes error:', error);
        res.status(500).json({ error: 'Failed to save sidenotes' });
    }
});

// Add single sidenote
app.post('/api/admin/proposals/:partnerId/sidenotes', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        const partnerId = req.params.partnerId;
        const { sidenote } = req.body;
        
        await db.collection('proposals').updateOne(
            { partnerId },
            { 
                $push: { sidenotes: { ...sidenote, id: Date.now(), timestamp: new Date() } },
                $set: { updatedAt: new Date() }
            },
            { upsert: true }
        );
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Add sidenote error:', error);
        res.status(500).json({ error: 'Failed to add sidenote' });
    }
});

// Fallback draft generator (no API key needed)
function generateFallbackDraft(type, partner, history = []) {
    const name = partner.name || 'there';
    const org = partner.organization || 'your organization';
    const isMedia = partner.type === 'media';
    const hasHistory = history && history.length > 0;
    
    switch (type) {
        case 'pitch':
            if (isMedia) {
                return `Dear ${name},

I'm reaching out from Luminary AI Technologies with a story I believe would resonate with ${org}'s audience.

After three years of stealth development—deliberately avoiding institutional funding to maintain complete independence—we're preparing to launch a suite of AI platforms designed to democratize access to sophisticated tools that have historically been locked behind institutional paywalls.

Our first platform, Vestiq, brings financial market intelligence capabilities previously available only to hedge funds to individual investors and entrepreneurs. But that's just the beginning: we're building across legal intelligence, e-commerce analytics, and development infrastructure.

The angle that might interest you: this is an outsider's challenge to the establishment. Zero Silicon Valley money. Zero Wall Street backing. Just a mission to build technology "for the people, not power."

I'd welcome the opportunity to share more about our launch timeline and vision. Would you have 15 minutes this week for a call?

Best regards,
Ben Hizer
Founder, Luminary AI Technologies
media@luminary-tech.ai`;
            } else {
                return `Dear ${name},

I'm reaching out to explore a potential partnership between Luminary AI Technologies and ${org}.

We're building AI-powered platforms that democratize access to sophisticated tools—financial market intelligence, legal and regulatory analysis, e-commerce optimization—capabilities traditionally available only to large institutions.

For ${org}, a partnership could provide:

• Student access to professional-grade AI platforms (Vestiq for finance students, Legal Insights for law, etc.)
• Real-world infrastructure experience that translates directly to career readiness
• Research collaboration opportunities with our development team
• Potential internship and employment pipeline as we scale

We're particularly interested in working with universities because our mission is about accessibility. Students shouldn't have to wait until they're at a hedge fund to use these tools.

Would you be open to a conversation about how we might structure a pilot program?

Best regards,
Ben Hizer
Founder, Luminary AI Technologies`;
            }
            
        case 'followup':
            if (hasHistory) {
                const lastMessage = history[history.length - 1];
                return `Hi ${name},

I wanted to follow up on our conversation${lastMessage ? ` from ${new Date(lastMessage.date).toLocaleDateString()}` : ''}.

${partner.status === 'responded' ? 
`I've been thinking about your questions and wanted to provide some additional context that might be helpful.` :
`I know you're busy, but I wanted to make sure this didn't slip through the cracks.`}

We're moving quickly toward our public launch, and I'd genuinely value ${org}'s ${isMedia ? 'perspective on the story' : 'partnership as we grow'}.

Is there anything specific I can provide to help move the conversation forward? Even a brief call would be valuable.

Best,
Ben Hizer
Luminary AI Technologies`;
            } else {
                return `Hi ${name},

I wanted to follow up on my previous message about Luminary AI Technologies.

We're moving toward our public launch, and I'd love to connect before things get too hectic. ${isMedia ? 
`I think there's a compelling story here about challenging the institutional status quo in AI.` :
`I believe there's real value we could provide to ${org}'s students and programs.`}

Would you have 15 minutes this week for a quick call? I'm happy to work around your schedule.

Best,
Ben Hizer
Luminary AI Technologies`;
            }
            
        case 'contract':
            return `PARTNERSHIP AGREEMENT OUTLINE
${org} & Luminary AI Technologies
Draft for Discussion

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. PARTNERSHIP OVERVIEW

This agreement establishes a collaborative partnership between ${org} and Luminary AI Technologies ("Luminary") to ${isMedia ? 
'facilitate ongoing media coverage and information sharing' : 
'provide platform access and educational collaboration'}.

Effective Date: [To be determined]
Initial Term: 12 months with renewal option

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

2. SCOPE OF COLLABORATION

${isMedia ? `
Media Partnership Scope:
• Priority access to company announcements and launches
• Exclusive interview opportunities with founder Ben Hizer
• Early access to platform demonstrations and data
• Background briefings on industry developments
• Quarterly update calls on company progress
` : `
Academic Partnership Scope:
• Platform access for [specific programs/departments]
• Student accounts for Vestiq, Legal Insights, and future platforms
• Faculty research collaboration opportunities
• Guest lecture and workshop participation
• Internship program development
`}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

3. LUMINARY OBLIGATIONS

Luminary agrees to:
${isMedia ? `
• Provide ${org} with advance notice of major announcements (minimum 48 hours when possible)
• Make spokesperson available for interviews and fact-checking
• Share relevant data and metrics for reporting
• Offer exclusive angles where appropriate
• Respond to media inquiries within 24 business hours
` : `
• Provide and maintain platform access for agreed users
• Deliver training and onboarding support
• Provide technical support during business hours
• Share relevant updates and new features
• Collaborate on curriculum integration where appropriate
`}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

4. ${isMedia ? 'MEDIA OUTLET' : 'UNIVERSITY'} OBLIGATIONS

${org} agrees to:
${isMedia ? `
• Provide fair and accurate coverage based on information shared
• Offer reasonable opportunity for comment on stories
• Maintain agreed embargoes and timing
• Credit Luminary appropriately in coverage
• Designate primary point of contact for coordination
` : `
• Designate program coordinator and technical contact
• Promote platform availability to eligible students/faculty
• Provide feedback on platform utility and improvements
• Participate in case studies and testimonials (optional)
• Collaborate on program development and outcomes tracking
`}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

5. CONFIDENTIALITY

Both parties agree to maintain confidentiality of:
• Non-public business information
• User data and analytics
• Strategic plans shared in confidence
• Terms of this partnership

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

6. TERM AND RENEWAL

• Initial term: 12 months from effective date
• Automatic renewal for additional 12-month periods unless either party provides 30 days written notice
• Either party may terminate with 30 days written notice

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

7. NEXT STEPS

To proceed:
1. Review and discuss this outline
2. Identify any modifications or additions needed
3. Formalize agreement with signatures
4. Schedule kickoff call

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This document is an outline for discussion purposes and does not constitute a binding legal agreement until formally executed by both parties.

Questions? Contact: media@luminary-tech.ai`;
            
        case 'research':
            return `RESEARCH BRIEF: ${org}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️  ENHANCED RESEARCH AVAILABLE

For comprehensive, real-time research on ${org}, please ensure the Perplexity API is configured. The AI research function provides:

• Current news and recent coverage
• Key personnel and contact information  
• Specific partnership angles
• Competitive intelligence
• Social media presence analysis

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

BASIC PROFILE:

Organization: ${org}
Type: ${isMedia ? 'Media Outlet' : 'University'}
Category: ${partner.category || 'Not specified'}
Location: ${partner.location || 'Not specified'}
Current Status: ${partner.status || 'Pending'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MANUAL RESEARCH CHECKLIST:

${isMedia ? `
□ Visit ${org}'s website
□ Search recent articles about AI, fintech, startups
□ Check editorial team on LinkedIn
□ Review their social media presence
□ Look for similar company coverage
□ Identify relevant journalists by beat
` : `
□ Review ${org}'s academic programs
□ Search for AI/ML/fintech research
□ Check entrepreneurship/innovation programs
□ Find industry partnership office
□ Look for relevant faculty researchers
□ Review career services partnerships
`}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LUMINARY TALKING POINTS FOR ${org.toUpperCase()}:

${isMedia ? `
Suggested Angles:
1. "Outsider challenges institutional AI dominance"
2. "Self-funded founder rejects Silicon Valley playbook"
3. "Democratizing hedge fund tools for retail investors"
4. "The anti-establishment AI company"

Key Stats to Share:
• 3 years stealth development
• Zero institutional funding
• 4 integrated platforms
• Focus on individual users, not institutions
` : `
Partnership Value Props:
1. Free/subsidized platform access for students
2. Real-world AI tool experience
3. Research collaboration potential
4. Career pipeline opportunity

Relevant Platforms:
• Vestiq → Business/Finance students
• Legal Insights → Law/Policy students
• Blue Haven → Marketing/E-commerce
• Luminary Studios → CS/Engineering
`}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

To unlock full AI-powered research:
Add PERPLEXITY_API_KEY to your environment variables.`;
            
        default:
            return 'Draft type not recognized.';
    }
}

// ===== PRESS RELEASE / EMAIL BLAST ENDPOINTS =====

// Helper: Send email via Resend
async function sendEmailViaResend(to, subject, htmlBody, textBody, replyTo) {
    if (!config.resendApiKey) {
        throw new Error('Resend API key not configured');
    }
    
    const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${config.resendApiKey}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            from: `${config.senderName} <${config.senderEmail}>`,
            to: to,
            subject: subject,
            html: htmlBody,
            text: textBody,
            reply_to: replyTo || config.senderEmail
        })
    });
    
    const result = await response.json();
    
    if (!response.ok) {
        throw new Error(result.message || 'Failed to send email');
    }
    
    return result;
}

// Helper: Replace personalization tokens
function personalizeContent(template, recipient) {
    let content = template;
    content = content.replace(/\{\{name\}\}/gi, recipient.recipientName || recipient.contactName || 'Editor');
    content = content.replace(/\{\{outlet\}\}/gi, recipient.organizationName || recipient.recipientName || '');
    content = content.replace(/\{\{first_name\}\}/gi, (recipient.recipientName || 'Editor').split(' ')[0]);
    content = content.replace(/\{\{category\}\}/gi, recipient.category || recipient.beat || '');
    content = content.replace(/\{\{location\}\}/gi, recipient.location || recipient.region || '');
    return content;
}

// Get media contacts for press release
app.get('/api/admin/press/recipients', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        const { category, hasEmail } = req.query;
        
        let query = { recipientType: 'media' };
        
        if (category && category !== 'all') {
            query.category = category;
        }
        
        // Get all media partners
        const partners = await db.collection('partners').find(query).toArray();
        
        // Filter to those with email addresses
        const recipients = partners.filter(p => {
            // Check if they have an email (you may need to add email field to your partners)
            return p.email || p.contactEmail || (p.accessKey && p.accessKey.includes('@'));
        }).map(p => ({
            id: p._id,
            name: p.recipientName,
            organization: p.organizationName,
            email: p.email || p.contactEmail,
            category: p.category,
            location: p.location,
            status: p.status
        }));
        
        // Get unique categories for filtering
        const categories = [...new Set(partners.map(p => p.category).filter(Boolean))];
        
        res.json({
            recipients,
            totalMedia: partners.length,
            withEmail: recipients.length,
            categories
        });
        
    } catch (error) {
        console.error('Get press recipients error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Send press release
app.post('/api/admin/press/send', requireAdmin, async (req, res) => {
    try {
        const { subject, htmlBody, textBody, recipientIds, sendToAll, category, testEmail } = req.body;
        
        if (!subject || (!htmlBody && !textBody)) {
            return res.status(400).json({ error: 'Subject and body are required' });
        }
        
        const db = client.db(config.dbName);
        
        // If test email, just send to that address
        if (testEmail) {
            try {
                const result = await sendEmailViaResend(
                    testEmail,
                    `[TEST] ${subject}`,
                    htmlBody,
                    textBody
                );
                return res.json({ 
                    success: true, 
                    message: 'Test email sent',
                    testEmail,
                    resendId: result.id
                });
            } catch (error) {
                return res.status(500).json({ error: `Failed to send test: ${error.message}` });
            }
        }
        
        // Get recipients
        let query = { recipientType: 'media' };
        if (!sendToAll && recipientIds && recipientIds.length > 0) {
            query._id = { $in: recipientIds.map(id => new ObjectId(id)) };
        } else if (category && category !== 'all') {
            query.category = category;
        }
        
        const partners = await db.collection('partners').find(query).toArray();
        const recipients = partners.filter(p => p.email || p.contactEmail);
        
        if (recipients.length === 0) {
            return res.status(400).json({ error: 'No recipients with email addresses found' });
        }
        
        // Create press release record
        const pressRelease = {
            subject,
            htmlBody,
            textBody,
            category: category || 'all',
            sentAt: new Date(),
            sentBy: 'admin',
            recipientCount: recipients.length,
            status: 'sending',
            results: []
        };
        
        const insertResult = await db.collection('press_releases').insertOne(pressRelease);
        const pressReleaseId = insertResult.insertedId;
        
        // Send emails (in batches to avoid rate limits)
        const results = [];
        const batchSize = 10;
        const delayBetweenBatches = 1000; // 1 second
        
        for (let i = 0; i < recipients.length; i += batchSize) {
            const batch = recipients.slice(i, i + batchSize);
            
            const batchResults = await Promise.allSettled(
                batch.map(async (recipient) => {
                    const email = recipient.email || recipient.contactEmail;
                    const personalizedSubject = personalizeContent(subject, recipient);
                    const personalizedHtml = personalizeContent(htmlBody, recipient);
                    const personalizedText = textBody ? personalizeContent(textBody, recipient) : null;
                    
                    try {
                        const result = await sendEmailViaResend(
                            email,
                            personalizedSubject,
                            personalizedHtml,
                            personalizedText
                        );
                        return {
                            recipientId: recipient._id,
                            email,
                            name: recipient.recipientName,
                            status: 'sent',
                            resendId: result.id
                        };
                    } catch (error) {
                        return {
                            recipientId: recipient._id,
                            email,
                            name: recipient.recipientName,
                            status: 'failed',
                            error: error.message
                        };
                    }
                })
            );
            
            results.push(...batchResults.map(r => r.value || r.reason));
            
            // Delay between batches
            if (i + batchSize < recipients.length) {
                await new Promise(resolve => setTimeout(resolve, delayBetweenBatches));
            }
        }
        
        // Update press release record with results
        const sentCount = results.filter(r => r.status === 'sent').length;
        const failedCount = results.filter(r => r.status === 'failed').length;
        
        await db.collection('press_releases').updateOne(
            { _id: pressReleaseId },
            {
                $set: {
                    status: 'completed',
                    results,
                    sentCount,
                    failedCount,
                    completedAt: new Date()
                }
            }
        );
        
        res.json({
            success: true,
            pressReleaseId,
            totalRecipients: recipients.length,
            sent: sentCount,
            failed: failedCount,
            results
        });
        
    } catch (error) {
        console.error('Send press release error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Get press release history
app.get('/api/admin/press/history', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        
        const pressReleases = await db.collection('press_releases')
            .find({})
            .sort({ sentAt: -1 })
            .limit(50)
            .toArray();
        
        res.json(pressReleases);
        
    } catch (error) {
        console.error('Get press history error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get single press release details
app.get('/api/admin/press/:id', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        
        const pressRelease = await db.collection('press_releases').findOne({
            _id: new ObjectId(req.params.id)
        });
        
        if (!pressRelease) {
            return res.status(404).json({ error: 'Press release not found' });
        }
        
        res.json(pressRelease);
        
    } catch (error) {
        console.error('Get press release error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Save press release as draft
app.post('/api/admin/press/draft', requireAdmin, async (req, res) => {
    try {
        const { subject, htmlBody, textBody, category, name } = req.body;
        
        const db = client.db(config.dbName);
        
        const draft = {
            name: name || subject || 'Untitled Draft',
            subject,
            htmlBody,
            textBody,
            category,
            createdAt: new Date(),
            updatedAt: new Date(),
            isDraft: true
        };
        
        const result = await db.collection('press_releases').insertOne(draft);
        
        res.json({ success: true, draftId: result.insertedId });
        
    } catch (error) {
        console.error('Save draft error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get drafts
app.get('/api/admin/press/drafts', requireAdmin, async (req, res) => {
    try {
        const db = client.db(config.dbName);
        
        const drafts = await db.collection('press_releases')
            .find({ isDraft: true })
            .sort({ updatedAt: -1 })
            .toArray();
        
        res.json(drafts);
        
    } catch (error) {
        console.error('Get drafts error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Add/Update email for a media partner
app.patch('/api/admin/partners/:id/email', requireAdmin, async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email || !email.includes('@')) {
            return res.status(400).json({ error: 'Valid email required' });
        }
        
        const db = client.db(config.dbName);
        
        const result = await db.collection('partners').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { email: email.toLowerCase().trim() } }
        );
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Partner not found' });
        }
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Update email error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Bulk import emails for media partners
app.post('/api/admin/partners/import-emails', requireAdmin, async (req, res) => {
    try {
        const { emails } = req.body; // Array of { name, email } or { organization, email }
        
        if (!emails || !Array.isArray(emails)) {
            return res.status(400).json({ error: 'Emails array required' });
        }
        
        const db = client.db(config.dbName);
        let updated = 0;
        let notFound = 0;
        
        for (const item of emails) {
            if (!item.email) continue;
            
            // Try to match by organization name or recipient name
            const query = {
                recipientType: 'media',
                $or: [
                    { organizationName: { $regex: new RegExp(item.name || item.organization, 'i') } },
                    { recipientName: { $regex: new RegExp(item.name || item.organization, 'i') } }
                ]
            };
            
            const result = await db.collection('partners').updateOne(
                query,
                { $set: { email: item.email.toLowerCase().trim() } }
            );
            
            if (result.matchedCount > 0) {
                updated++;
            } else {
                notFound++;
            }
        }
        
        res.json({ success: true, updated, notFound });
        
    } catch (error) {
        console.error('Bulk import emails error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== START SERVER =====

async function start() {
    try {
        await connectDB();
        
        // Debug: Log API key status (first 10 chars only for security)
        const pplxKey = config.perplexityApiKey;
        console.log(`Perplexity API Key: ${pplxKey ? pplxKey.substring(0, 10) + '...' + ' (length: ' + pplxKey.length + ')' : 'NOT SET'}`);
        
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
