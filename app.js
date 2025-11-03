// app.js - Main Application Logic for PN-App Physiotherapy System
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const PDFDocument = require('pdfkit');
const QRCode = require('qrcode');
const moment = require('moment');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();


// add near the top, after `const app = express();`
const cookieParser = require('cookie-parser');

app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));


// ========================================
// UTILITY FUNCTIONS
// ========================================

// Generate unique codes
const generatePTNumber = () => {
    const timestamp = moment().format('YYYYMMDDHHmmss');
    const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
    return `PT${timestamp}${random}`;
};

const generatePNCode = () => {
    const timestamp = moment().format('YYYYMMDDHHmmss');
    const random = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
    return `PN-${timestamp}-${random}`;
};

// Hash password
const hashPassword = async (password) => {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
};

// Verify password
const verifyPassword = async (password, hash) => {
    return await bcrypt.compare(password, hash);
};

// Generate JWT token
const generateToken = (user) => {
    const payload = {
        id: user.id,
        email: user.email,
        role: user.role,
        clinic_id: user.clinic_id
    };
    return jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN || '7d'
    });
};

// ========================================
// MIDDLEWARE
// ========================================

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        // Check for token in cookies for web pages
        const cookieToken = req.cookies?.authToken;
        if (!cookieToken) {
            if (req.path.startsWith('/api/')) {
                return res.status(401).json({ error: 'Access token required' });
            }
            return res.redirect('/login');
        }
        req.token = cookieToken;
    } else {
        req.token = token;
    }
    
    jwt.verify(req.token || token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            if (req.path.startsWith('/api/')) {
                return res.status(403).json({ error: 'Invalid or expired token' });
            }
            return res.redirect('/login');
        }
        req.user = user;
        next();
    });
};

// Role-based access control
const authorize = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        
        next();
    };
};

// Clinic access control
const checkClinicAccess = async (req, res, next) => {
    try {
        const db = req.app.locals.db;
        const userId = req.user.id;
        const clinicId = req.params.clinicId || req.body.clinic_id || req.query.clinic_id;
        
        if (!clinicId) {
            return next();
        }
        
        // Admin has access to all clinics
        if (req.user.role === 'ADMIN') {
            return next();
        }
        
        // Check if user's primary clinic matches
        if (req.user.clinic_id == clinicId) {
            return next();
        }
        
        // Check user_clinic_grants
        const [grants] = await db.execute(
            'SELECT * FROM user_clinic_grants WHERE user_id = ? AND clinic_id = ?',
            [userId, clinicId]
        );
        
        if (grants.length > 0) {
            return next();
        }
        
        return res.status(403).json({ error: 'No access to this clinic' });
    } catch (error) {
        console.error('Clinic access check error:', error);
        return res.status(500).json({ error: 'Access verification failed' });
    }
};

// File upload configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, process.env.UPLOAD_DIR || './uploads');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10485760 // 10MB
    },
    fileFilter: function (req, file, cb) {
        const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPEG, PNG, GIF, PDF, DOC, DOCX are allowed.'));
        }
    }
});

// Audit logging
const auditLog = async (db, userId, action, entityType, entityId, oldValues = null, newValues = null, req = null) => {
    try {
        const ipAddress = req ? (req.headers['x-forwarded-for'] || req.connection.remoteAddress) : null;
        const userAgent = req ? req.headers['user-agent'] : null;
        
        await db.execute(
            `INSERT INTO audit_logs (user_id, action, entity_type, entity_id, old_values, new_values, ip_address, user_agent) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                userId,
                action,
                entityType,
                entityId,
                oldValues ? JSON.stringify(oldValues) : null,
                newValues ? JSON.stringify(newValues) : null,
                ipAddress,
                userAgent
            ]
        );
    } catch (error) {
        console.error('Audit logging error:', error);
    }
};

// ========================================
// AUTHENTICATION ROUTES
// ========================================

// Login
app.post('/api/auth/login', [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        const { email, password } = req.body;
        const db = req.app.locals.db;
        
        // Get user
        const [users] = await db.execute(
            `SELECT u.*, c.name as clinic_name 
             FROM users u 
             LEFT JOIN clinics c ON u.clinic_id = c.id 
             WHERE u.email = ? AND u.active = 1`,
            [email]
        );
        
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const user = users[0];
        
        // Verify password
        const validPassword = await verifyPassword(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Update last login
        await db.execute(
            'UPDATE users SET last_login = NOW() WHERE id = ?',
            [user.id]
        );
        
        // Generate token
        const token = generateToken(user);
        
        // Get user's clinic grants
        const [grants] = await db.execute(
            `SELECT g.clinic_id, c.name as clinic_name 
             FROM user_clinic_grants g 
             JOIN clinics c ON g.clinic_id = c.id 
             WHERE g.user_id = ?`,
            [user.id]
        );
        
        // Audit log
        await auditLog(db, user.id, 'LOGIN', 'user', user.id, null, null, req);
        
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: user.email,
                role: user.role,
                name: `${user.first_name} ${user.last_name}`,
                clinic_id: user.clinic_id,
                clinic_name: user.clinic_name,
                clinic_grants: grants
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Logout
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        await auditLog(db, req.user.id, 'LOGOUT', 'user', req.user.id, null, null, req);
        
        res.clearCookie('authToken');
        res.json({ success: true, message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Logout failed' });
    }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        
        const [users] = await db.execute(
            `SELECT u.id, u.email, u.role, u.first_name, u.last_name, u.clinic_id,
                    c.name as clinic_name, u.phone, u.license_number
             FROM users u
             LEFT JOIN clinics c ON u.clinic_id = c.id
             WHERE u.id = ?`,
            [req.user.id]
        );
        
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Get clinic grants
        const [grants] = await db.execute(
            `SELECT g.clinic_id, c.name as clinic_name
             FROM user_clinic_grants g
             JOIN clinics c ON g.clinic_id = c.id
             WHERE g.user_id = ?`,
            [req.user.id]
        );
        
        res.json({
            ...users[0],
            clinic_grants: grants
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ error: 'Failed to get user information' });
    }
});

// Change password
app.post('/api/auth/change-password', authenticateToken, [
    body('current_password').notEmpty(),
    body('new_password').isLength({ min: 6 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        const { current_password, new_password } = req.body;
        const db = req.app.locals.db;
        
        // Get current password hash
        const [users] = await db.execute(
            'SELECT password_hash FROM users WHERE id = ?',
            [req.user.id]
        );
        
        // Verify current password
        const validPassword = await verifyPassword(current_password, users[0].password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }
        
        // Hash new password
        const newHash = await hashPassword(new_password);
        
        // Update password
        await db.execute(
            'UPDATE users SET password_hash = ?, updated_at = NOW() WHERE id = ?',
            [newHash, req.user.id]
        );
        
        await auditLog(db, req.user.id, 'CHANGE_PASSWORD', 'user', req.user.id, null, null, req);
        
        res.json({ success: true, message: 'Password changed successfully' });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// Update profile
app.put('/api/auth/update-profile', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const userId = req.user.id;
        const { first_name, last_name, phone, license_number } = req.body;
        
        const updateFields = [];
        const updateValues = [];
        
        if (first_name) {
            updateFields.push('first_name = ?');
            updateValues.push(first_name);
        }
        if (last_name) {
            updateFields.push('last_name = ?');
            updateValues.push(last_name);
        }
        if (phone !== undefined) {
            updateFields.push('phone = ?');
            updateValues.push(phone);
        }
        if (license_number !== undefined) {
            updateFields.push('license_number = ?');
            updateValues.push(license_number);
        }
        
        if (updateFields.length === 0) {
            return res.status(400).json({ error: 'No fields to update' });
        }
        
        updateFields.push('updated_at = NOW()');
        updateValues.push(userId);
        
        await db.execute(
            `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`,
            updateValues
        );
        
        res.json({ success: true, message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// ========================================
// PATIENT MANAGEMENT ROUTES
// ========================================

// Get all patients
app.get('/api/patients', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { clinic_id, search, page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;

        let query = `
            SELECT p.*, c.name as clinic_name,
                   CONCAT(u.first_name, ' ', u.last_name) as created_by_name
            FROM patients p
            JOIN clinics c ON p.clinic_id = c.id
            JOIN users u ON p.created_by = u.id
            WHERE 1=1
        `;
        let countQuery = 'SELECT COUNT(*) as total FROM patients p WHERE 1=1';
        const params = [];
        const countParams = [];

        // Role-based filtering for patients
        // ADMIN: See all patients from all clinics
        // CLINIC: See only patients registered to their clinic
        // PT: See all patients (can access everything)

        if (req.user.role === 'CLINIC') {
            // CLINIC users can only see their own clinic's patients
            if (!req.user.clinic_id) {
                return res.status(403).json({
                    error: 'CLINIC user must be assigned to a clinic'
                });
            }
            query += ' AND p.clinic_id = ?';
            countQuery += ' AND p.clinic_id = ?';
            params.push(req.user.clinic_id);
            countParams.push(req.user.clinic_id);
        }
        // ADMIN and PT roles: No filtering, they see all patients

        // Filter by specific clinic (if provided in query)
        if (clinic_id && req.user.role !== 'CLINIC') {
            query += ' AND p.clinic_id = ?';
            countQuery += ' AND p.clinic_id = ?';
            params.push(clinic_id);
            countParams.push(clinic_id);
        }
        
        // Search
        if (search) {
            const searchPattern = `%${search}%`;
            query += ' AND (p.hn LIKE ? OR p.pt_number LIKE ? OR p.first_name LIKE ? OR p.last_name LIKE ? OR p.diagnosis LIKE ?)';
            countQuery += ' AND (p.hn LIKE ? OR p.pt_number LIKE ? OR p.first_name LIKE ? OR p.last_name LIKE ? OR p.diagnosis LIKE ?)';
            params.push(searchPattern, searchPattern, searchPattern, searchPattern, searchPattern);
            countParams.push(searchPattern, searchPattern, searchPattern, searchPattern, searchPattern);
        }
        
        // Get total count
        const [countResult] = await db.execute(countQuery, countParams);
        const total = countResult[0].total;
        
        // Add pagination
        query += ' ORDER BY p.created_at DESC LIMIT ? OFFSET ?';
        params.push(parseInt(limit), offset);
        
        const [patients] = await db.execute(query, params);
        
        res.json({
            patients,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Get patients error:', error);
        res.status(500).json({ error: 'Failed to retrieve patients' });
    }
});

// Search patients (for appointment booking)
app.get('/api/patients/search', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { q } = req.query;

        if (!q || q.length < 2) {
            return res.json([]);
        }

        const searchPattern = `%${q}%`;
        const [patients] = await db.execute(
            `SELECT p.id, p.hn, p.pt_number, p.first_name, p.last_name, p.dob, p.gender, p.diagnosis
             FROM patients p
             WHERE p.hn LIKE ? OR p.pt_number LIKE ? OR p.first_name LIKE ? OR p.last_name LIKE ?
             ORDER BY p.last_name, p.first_name
             LIMIT 20`,
            [searchPattern, searchPattern, searchPattern, searchPattern]
        );

        res.json(patients);
    } catch (error) {
        console.error('Search patients error:', error);
        res.status(500).json({ error: 'Failed to search patients' });
    }
});

// Get single patient
app.get('/api/patients/:id', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;
        
        const [patients] = await db.execute(
            `SELECT p.*, c.name as clinic_name,
                    CONCAT(u.first_name, ' ', u.last_name) as created_by_name
             FROM patients p
             JOIN clinics c ON p.clinic_id = c.id
             JOIN users u ON p.created_by = u.id
             WHERE p.id = ?`,
            [id]
        );
        
        if (patients.length === 0) {
            return res.status(404).json({ error: 'Patient not found' });
        }
        
        // Check clinic access
        const patient = patients[0];
        if (req.user.role !== 'ADMIN') {
            const [grants] = await db.execute(
                'SELECT clinic_id FROM user_clinic_grants WHERE user_id = ? AND clinic_id = ? UNION SELECT ? as clinic_id WHERE ? = ?',
                [req.user.id, patient.clinic_id, req.user.clinic_id, req.user.clinic_id, patient.clinic_id]
            );
            
            if (grants.length === 0) {
                return res.status(403).json({ error: 'No access to this patient' });
            }
        }
        
        res.json(patient);
    } catch (error) {
        console.error('Get patient error:', error);
        res.status(500).json({ error: 'Failed to retrieve patient' });
    }
});

// Create patient
app.post('/api/patients', authenticateToken, [
    body('hn').notEmpty(),
    body('first_name').notEmpty(),
    body('last_name').notEmpty(),
    body('dob').isDate(),
    body('diagnosis').notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        const db = req.app.locals.db;
        const ptNumber = generatePTNumber();
        
        // Role-based clinic assignment
        // ADMIN: Can create patients for any clinic (clinic_id from request)
        // CLINIC: Can only create patients for their own clinic
        // PT: Can create patients for any clinic (clinic_id from request)

        let clinicId;

        if (req.user.role === 'CLINIC') {
            // CLINIC users can only create patients for their own clinic
            if (!req.user.clinic_id) {
                return res.status(403).json({
                    error: 'CLINIC user must be assigned to a clinic'
                });
            }
            clinicId = req.user.clinic_id; // Always use their clinic
        } else {
            // ADMIN and PT can specify clinic_id
            clinicId = req.body.clinic_id;
            if (!clinicId) {
                return res.status(400).json({
                    error: 'Clinic ID is required for patient registration'
                });
            }
        }
        
        const patientData = {
            ...req.body,
            pt_number: ptNumber,
            clinic_id: clinicId,
            created_by: req.user.id
        };
        
        const [result] = await db.execute(
            `INSERT INTO patients (
                hn, pt_number, pid, passport_no, title, first_name, last_name, 
                dob, gender, phone, email, address, emergency_contact, emergency_phone,
                diagnosis, rehab_goal, rehab_goal_other, body_area, frequency, 
                expected_duration, doctor_note, precaution, contraindication, 
                medical_history, clinic_id, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                patientData.hn, ptNumber, patientData.pid, patientData.passport_no,
                patientData.title, patientData.first_name, patientData.last_name,
                patientData.dob, patientData.gender, patientData.phone, patientData.email,
                patientData.address, patientData.emergency_contact, patientData.emergency_phone,
                patientData.diagnosis, patientData.rehab_goal, patientData.rehab_goal_other,
                patientData.body_area, patientData.frequency, patientData.expected_duration,
                patientData.doctor_note, patientData.precaution, patientData.contraindication,
                patientData.medical_history, clinicId, req.user.id
            ]
        );
        
        await auditLog(db, req.user.id, 'CREATE', 'patient', result.insertId, null, patientData, req);
        
        res.status(201).json({
            success: true,
            message: 'Patient created successfully',
            patient_id: result.insertId,
            pt_number: ptNumber
        });
    } catch (error) {
        console.error('Create patient error:', error);
        res.status(500).json({ error: 'Failed to create patient' });
    }
});

// Update patient
app.put('/api/patients/:id', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;

        // Get current patient data
        const [patients] = await db.execute(
            'SELECT * FROM patients WHERE id = ?',
            [id]
        );

        if (patients.length === 0) {
            return res.status(404).json({ error: 'Patient not found' });
        }

        const oldData = patients[0];

        // Check clinic access
        if (req.user.role !== 'ADMIN') {
            const [grants] = await db.execute(
                'SELECT clinic_id FROM user_clinic_grants WHERE user_id = ? AND clinic_id = ? UNION SELECT ? as clinic_id WHERE ? = ?',
                [req.user.id, oldData.clinic_id, req.user.clinic_id, req.user.clinic_id, oldData.clinic_id]
            );

            if (grants.length === 0) {
                return res.status(403).json({ error: 'No access to update this patient' });
            }
        }

        // Update patient
        const updateFields = [];
        const updateValues = [];
        const allowedFields = [
            'pid', 'passport_no', 'title', 'first_name', 'last_name', 'gender',
            'phone', 'email', 'address', 'emergency_contact', 'emergency_phone',
            'diagnosis', 'rehab_goal', 'rehab_goal_other', 'body_area', 'frequency',
            'expected_duration', 'doctor_note', 'precaution', 'contraindication', 'medical_history'
        ];

        for (const field of allowedFields) {
            if (req.body[field] !== undefined) {
                updateFields.push(`${field} = ?`);
                updateValues.push(req.body[field]);
            }
        }

        if (updateFields.length === 0) {
            return res.status(400).json({ error: 'No fields to update' });
        }

        updateFields.push('updated_at = NOW()');
        updateValues.push(id);

        await db.execute(
            `UPDATE patients SET ${updateFields.join(', ')} WHERE id = ?`,
            updateValues
        );

        await auditLog(db, req.user.id, 'UPDATE', 'patient', id, oldData, req.body, req);

        res.json({ success: true, message: 'Patient updated successfully' });
    } catch (error) {
        console.error('Update patient error:', error);
        res.status(500).json({ error: 'Failed to update patient' });
    }
});

// Delete patient (ADMIN only)
app.delete('/api/patients/:id', authenticateToken, authorize('ADMIN'), async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;

        // Get current patient data for audit log
        const [patients] = await db.execute(
            'SELECT * FROM patients WHERE id = ?',
            [id]
        );

        if (patients.length === 0) {
            return res.status(404).json({ error: 'Patient not found' });
        }

        const patientData = patients[0];

        // Check if patient has associated PN cases
        const [pnCases] = await db.execute(
            'SELECT COUNT(*) as count FROM pn_cases WHERE patient_id = ?',
            [id]
        );

        if (pnCases[0].count > 0) {
            return res.status(400).json({
                error: 'Cannot delete patient with associated PN cases. Please delete or reassign PN cases first.'
            });
        }

        // Delete the patient (CASCADE will handle related records if configured)
        await db.execute('DELETE FROM patients WHERE id = ?', [id]);

        // Log the deletion
        await auditLog(db, req.user.id, 'DELETE', 'patient', id, patientData, null, req);

        res.json({ success: true, message: 'Patient deleted successfully' });
    } catch (error) {
        console.error('Delete patient error:', error);
        res.status(500).json({ error: 'Failed to delete patient' });
    }
});

// ========================================
// PN CASE MANAGEMENT ROUTES
// ========================================

// Get PN cases
app.get('/api/pn', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const {
            status, clinic_id, from_date, to_date,
            search, page = 1, limit = 20
        } = req.query;

        const offset = (page - 1) * limit;

        let query = `
            SELECT
                pn.*,
                p.hn, p.pt_number, p.first_name, p.last_name,
                sc.name as source_clinic_name, sc.code as source_clinic_code,
                tc.name as target_clinic_name, tc.code as target_clinic_code,
                CONCAT(u.first_name, ' ', u.last_name) as created_by_name,
                (SELECT MAX(r.created_at)
                 FROM pn_reports r
                 JOIN pn_visits v ON r.visit_id = v.id
                 WHERE v.pn_id = pn.id) as last_report_at
            FROM pn_cases pn
            JOIN patients p ON pn.patient_id = p.id
            JOIN clinics sc ON pn.source_clinic_id = sc.id
            JOIN clinics tc ON pn.target_clinic_id = tc.id
            JOIN users u ON pn.created_by = u.id
            WHERE 1=1
        `;

        let countQuery = `
            SELECT COUNT(*) as total
            FROM pn_cases pn
            JOIN patients p ON pn.patient_id = p.id
            WHERE 1=1
        `;

        const params = [];
        const countParams = [];

        // Role-based filtering
        // ADMIN: See all data from every clinic
        // CLINIC: See only their own clinic's cases (source or target)
        // PT: See all cases (can access everything)

        if (req.user.role === 'CLINIC') {
            // CLINIC users can only see cases involving their clinic
            if (!req.user.clinic_id) {
                return res.status(403).json({
                    error: 'CLINIC user must be assigned to a clinic'
                });
            }
            query += ' AND (pn.source_clinic_id = ? OR pn.target_clinic_id = ?)';
            countQuery += ' AND (pn.source_clinic_id = ? OR pn.target_clinic_id = ?)';
            params.push(req.user.clinic_id, req.user.clinic_id);
            countParams.push(req.user.clinic_id, req.user.clinic_id);
        }
        // ADMIN and PT roles: No filtering, they see everything

        // Filter by specific clinic (if provided in query)
        if (clinic_id) {
            query += ' AND (pn.source_clinic_id = ? OR pn.target_clinic_id = ?)';
            countQuery += ' AND (pn.source_clinic_id = ? OR pn.target_clinic_id = ?)';
            params.push(clinic_id, clinic_id);
            countParams.push(clinic_id, clinic_id);
        }
        
        // Filter by status
        if (status) {
            query += ' AND pn.status = ?';
            countQuery += ' AND pn.status = ?';
            params.push(status);
            countParams.push(status);
        }
        
        // Date range filter
        if (from_date) {
            query += ' AND DATE(pn.created_at) >= ?';
            countQuery += ' AND DATE(pn.created_at) >= ?';
            params.push(from_date);
            countParams.push(from_date);
        }
        
        if (to_date) {
            query += ' AND DATE(pn.created_at) <= ?';
            countQuery += ' AND DATE(pn.created_at) <= ?';
            params.push(to_date);
            countParams.push(to_date);
        }
        
        // Search filter
        if (search) {
            const searchPattern = `%${search}%`;
            query += ` AND (p.hn LIKE ? OR p.first_name LIKE ? OR p.last_name LIKE ? 
                      OR pn.pn_code LIKE ? OR pn.diagnosis LIKE ? OR pn.purpose LIKE ?)`;
            countQuery += ` AND (p.hn LIKE ? OR p.first_name LIKE ? OR p.last_name LIKE ? 
                           OR pn.pn_code LIKE ? OR pn.diagnosis LIKE ? OR pn.purpose LIKE ?)`;
            const searchParams = Array(6).fill(searchPattern);
            params.push(...searchParams);
            countParams.push(...searchParams);
        }
        
        // Get total count
        const [countResult] = await db.execute(countQuery, countParams);
        const total = countResult[0].total;
        
        // Add ordering and pagination
        query += ' ORDER BY pn.created_at DESC LIMIT ? OFFSET ?';
        params.push(parseInt(limit), offset);
        
        const [cases] = await db.execute(query, params);

        // Get statistics with role-based filtering
        let statsQuery = `
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status = 'PENDING' THEN 1 ELSE 0 END) as waiting,
                SUM(CASE WHEN status = 'ACCEPTED' THEN 1 ELSE 0 END) as accepted,
                SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) as completed,
                SUM(CASE WHEN MONTH(created_at) = MONTH(CURRENT_DATE())
                    AND YEAR(created_at) = YEAR(CURRENT_DATE()) THEN 1 ELSE 0 END) as this_month
            FROM pn_cases
            WHERE 1=1
        `;

        const statsParams = [];

        // Apply same role-based filtering to statistics
        if (req.user.role === 'CLINIC') {
            statsQuery += ' AND (source_clinic_id = ? OR target_clinic_id = ?)';
            statsParams.push(req.user.clinic_id, req.user.clinic_id);
        }

        const [stats] = await db.execute(statsQuery, statsParams);
        
        res.json({
            cases,
            statistics: stats[0],
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Get PN cases error:', error);
        res.status(500).json({ error: 'Failed to retrieve PN cases' });
    }
});

// Create PN case
app.post('/api/pn', authenticateToken, [
    body('patient_id').isInt(),
    body('diagnosis').notEmpty(),
    body('purpose').notEmpty(),
    body('target_clinic_id').optional().isInt()  // Optional for CLINIC users
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        const db = req.app.locals.db;
        const pnCode = generatePNCode();
        
        // Get patient's clinic as source
        const [patients] = await db.execute(
            'SELECT clinic_id FROM patients WHERE id = ?',
            [req.body.patient_id]
        );
        
        if (patients.length === 0) {
            return res.status(404).json({ error: 'Patient not found' });
        }
        
        const patientClinicId = patients[0].clinic_id;

        // Role-based access control for PN case creation
        // ADMIN: Can create PN cases - any source to any target
        // CLINIC: Can only create PN cases for their own clinic as TARGET (receiving referrals)
        // PT: Can create PN cases for any patient to any clinic

        let sourceClinicId;
        let targetClinicId;

        if (req.user.role === 'CLINIC') {
            // CLINIC users create PN cases for their own clinic to treat
            // They are the TARGET clinic (receiving the patient)
            if (!req.user.clinic_id) {
                return res.status(403).json({
                    error: 'CLINIC user must be assigned to a clinic'
                });
            }

            // Source: Patient's current clinic
            sourceClinicId = patientClinicId;

            // Target: LOCKED to CLINIC user's clinic (they are receiving the patient)
            targetClinicId = req.user.clinic_id;

            // If target_clinic_id is provided in request, ignore it for CLINIC users
            if (req.body.target_clinic_id && req.body.target_clinic_id != req.user.clinic_id) {
                return res.status(403).json({
                    error: 'CLINIC users can only create PN cases for their own clinic'
                });
            }
        } else {
            // ADMIN and PT can specify any source and target
            sourceClinicId = patientClinicId;
            targetClinicId = req.body.target_clinic_id;

            if (!targetClinicId) {
                return res.status(400).json({
                    error: 'Target clinic ID is required'
                });
            }
        }

        // ******** FIX: REMOVED 'priority' from column list and '?' from values ********
        const [result] = await db.execute(
            `INSERT INTO pn_cases (
                pn_code, patient_id, diagnosis, purpose, status,
                source_clinic_id, target_clinic_id, referring_doctor,
                notes, current_medications, allergies,
                pn_precautions, pn_contraindications, treatment_goals,
                expected_outcomes, medical_notes, pain_scale, functional_status, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                pnCode,
                req.body.patient_id,
                req.body.diagnosis,
                req.body.purpose,
                'PENDING',
                sourceClinicId,
                targetClinicId,
                req.body.referring_doctor || null,
                // ******** FIX: REMOVED 'req.body.priority || 'NORMAL',' ********
                req.body.notes || null,
                req.body.current_medications || null,
                req.body.allergies || null,
                req.body.pn_precautions || null,
                req.body.pn_contraindications || null,
                req.body.treatment_goals || null,
                req.body.expected_outcomes || null,
                req.body.medical_notes || null,
                req.body.pain_scale || null,
                req.body.functional_status || null,
                req.user.id
            ]
        );
        
        await auditLog(db, req.user.id, 'CREATE', 'pn_case', result.insertId, null, req.body, req);
        
        res.status(201).json({
            success: true,
            message: 'PN case created successfully',
            pn_id: result.insertId,
            pn_code: pnCode
        });
    } catch (error) {
        console.error('Create PN case error:', error);
        res.status(500).json({ error: 'Failed to create PN case' });
    }
});

// Update PN case medical information
app.put('/api/pn/:id', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;

        // Get current PN case
        const [cases] = await db.execute(
            'SELECT * FROM pn_cases WHERE id = ?',
            [id]
        );

        if (cases.length === 0) {
            return res.status(404).json({ error: 'PN case not found' });
        }

        const oldCase = cases[0];

        // Check access - PT and ADMIN can update, CLINIC can update if it's their clinic
        if (req.user.role === 'CLINIC') {
            if (oldCase.target_clinic_id !== req.user.clinic_id && oldCase.source_clinic_id !== req.user.clinic_id) {
                return res.status(403).json({ error: 'No access to update this PN case' });
            }
        }

        // Allowed medical fields to update
        const allowedFields = [
            'diagnosis', 'purpose', 'referring_doctor', 'notes',
            'current_medications', 'allergies', 'pn_precautions', 'pn_contraindications',
            'treatment_goals', 'expected_outcomes', 'medical_notes', 'pain_scale', 'functional_status'
        ];

        const updateFields = [];
        const updateValues = [];

        for (const field of allowedFields) {
            if (req.body[field] !== undefined) {
                updateFields.push(`${field} = ?`);
                updateValues.push(req.body[field]);
            }
        }

        if (updateFields.length === 0) {
            return res.status(400).json({ error: 'No fields to update' });
        }

        updateFields.push('updated_at = NOW()');
        updateValues.push(id);

        await db.execute(
            `UPDATE pn_cases SET ${updateFields.join(', ')} WHERE id = ?`,
            updateValues
        );

        await auditLog(db, req.user.id, 'UPDATE', 'pn_case', id, oldCase, req.body, req);

        res.json({ success: true, message: 'PN case updated successfully' });
    } catch (error) {
        console.error('Update PN case error:', error);
        res.status(500).json({ error: 'Failed to update PN case' });
    }
});

// Update PN case status
app.patch('/api/pn/:id/status', authenticateToken, [
    body('status').isIn(['PENDING', 'ACCEPTED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'])
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const db = req.app.locals.db;
        const { id } = req.params;
        const { status, pt_diagnosis, pt_chief_complaint, pt_present_history, pt_pain_score, soap_notes } = req.body;

        // Get current case with clinic information
        const [cases] = await db.execute(
            `SELECT pn.*, sc.code as source_clinic_code, tc.code as target_clinic_code
             FROM pn_cases pn
             JOIN clinics sc ON pn.source_clinic_id = sc.id
             JOIN clinics tc ON pn.target_clinic_id = tc.id
             WHERE pn.id = ?`,
            [id]
        );

        if (cases.length === 0) {
            return res.status(404).json({ error: 'PN case not found' });
        }

        const oldCase = cases[0];

        // Check access - ADMIN and PT can change status
        if (req.user.role !== 'ADMIN' && req.user.role !== 'PT') {
            return res.status(403).json({ error: 'Only ADMIN or PT can change PN case status' });
        }

        // Update status with appropriate timestamp
        let updateQuery = 'UPDATE pn_cases SET status = ?, updated_at = NOW()';
        const updateParams = [status];

        // PENDING → ACCEPTED: Save PT information for non-CL001 clinics
        if (status === 'ACCEPTED' && oldCase.status === 'PENDING') {
            updateQuery += ', accepted_at = NOW()';

            // For non-CL001 clinics, require and save PT assessment information
            if (oldCase.source_clinic_code !== 'CL001' && oldCase.target_clinic_code !== 'CL001') {
                if (!pt_diagnosis || !pt_chief_complaint || !pt_present_history || pt_pain_score === undefined) {
                    return res.status(400).json({
                        error: 'PT assessment information required for non-CL001 clinics',
                        required_fields: ['pt_diagnosis', 'pt_chief_complaint', 'pt_present_history', 'pt_pain_score']
                    });
                }

                updateQuery += ', pt_diagnosis = ?, pt_chief_complaint = ?, pt_present_history = ?, pt_pain_score = ?';
                updateParams.push(pt_diagnosis, pt_chief_complaint, pt_present_history, pt_pain_score);
            }
        }
        // ACCEPTED → COMPLETED: Require SOAP notes for all clinics
        else if (status === 'COMPLETED' && oldCase.status === 'ACCEPTED') {
            updateQuery += ', completed_at = NOW()';

            // SOAP notes required for all clinics when completing
            if (!soap_notes || !soap_notes.subjective || !soap_notes.objective ||
                !soap_notes.assessment || !soap_notes.plan) {
                return res.status(400).json({
                    error: 'SOAP notes required when completing case',
                    required_fields: ['soap_notes.subjective', 'soap_notes.objective', 'soap_notes.assessment', 'soap_notes.plan']
                });
            }

            // Save SOAP notes to separate table
            await db.execute(
                `INSERT INTO pn_soap_notes (pn_id, subjective, objective, assessment, plan, timestamp, notes, created_by)
                 VALUES (?, ?, ?, ?, ?, NOW(), ?, ?)`,
                [id, soap_notes.subjective, soap_notes.objective, soap_notes.assessment,
                 soap_notes.plan, soap_notes.notes || '', req.user.id]
            );
        }
        else if (status === 'CANCELLED') {
            updateQuery += ', cancelled_at = NOW()';
            if (req.body.cancellation_reason) {
                updateQuery += ', cancellation_reason = ?';
                updateParams.push(req.body.cancellation_reason);
            }
        }

        updateQuery += ' WHERE id = ?';
        updateParams.push(id);

        await db.execute(updateQuery, updateParams);

        // Log status change in history
        await db.execute(
            `INSERT INTO pn_status_history (pn_id, old_status, new_status, changed_by, is_reversal)
             VALUES (?, ?, ?, ?, FALSE)`,
            [id, oldCase.status, status, req.user.id]
        );

        await auditLog(db, req.user.id, 'UPDATE_STATUS', 'pn_case', id,
                      { status: oldCase.status }, { status }, req);

        res.json({
            success: true,
            message: `PN case status updated to ${status}`
        });
    } catch (error) {
        console.error('Update PN status error:', error);
        res.status(500).json({ error: 'Failed to update PN case status' });
    }
});

// Reverse PN case status (ADMIN only)
app.post('/api/pn/:id/reverse-status', authenticateToken, authorize('ADMIN'), async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;
        const { reason } = req.body;

        if (!reason) {
            return res.status(400).json({ error: 'Reversal reason is required' });
        }

        // Get current case
        const [cases] = await db.execute(
            'SELECT * FROM pn_cases WHERE id = ?',
            [id]
        );

        if (cases.length === 0) {
            return res.status(404).json({ error: 'PN case not found' });
        }

        const currentCase = cases[0];

        // Only allow reversal from COMPLETED to ACCEPTED
        if (currentCase.status !== 'COMPLETED') {
            return res.status(400).json({
                error: 'Can only reverse COMPLETED cases back to ACCEPTED'
            });
        }

        // Update status back to ACCEPTED and clear completed_at
        await db.execute(
            `UPDATE pn_cases
             SET status = 'ACCEPTED',
                 completed_at = NULL,
                 is_reversed = TRUE,
                 last_reversal_reason = ?,
                 last_reversed_at = NOW(),
                 updated_at = NOW()
             WHERE id = ?`,
            [reason, id]
        );

        // Log status reversal in history
        await db.execute(
            `INSERT INTO pn_status_history (pn_id, old_status, new_status, changed_by, change_reason, is_reversal)
             VALUES (?, ?, ?, ?, ?, TRUE)`,
            [id, 'COMPLETED', 'ACCEPTED', req.user.id, reason]
        );

        await auditLog(db, req.user.id, 'REVERSE_STATUS', 'pn_case', id,
                      { status: 'COMPLETED' }, { status: 'ACCEPTED', reason }, req);

        res.json({
            success: true,
            message: 'Case status reversed to ACCEPTED. SOAP notes must be re-entered.'
        });
    } catch (error) {
        console.error('Reverse status error:', error);
        res.status(500).json({ error: 'Failed to reverse status' });
    }
});

// Get SOAP notes for a PN case
app.get('/api/pn/:id/soap-notes', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;

        const [notes] = await db.execute(
            `SELECT s.*, CONCAT(u.first_name, ' ', u.last_name) as created_by_name
             FROM pn_soap_notes s
             JOIN users u ON s.created_by = u.id
             WHERE s.pn_id = ?
             ORDER BY s.timestamp DESC`,
            [id]
        );

        res.json(notes);
    } catch (error) {
        console.error('Get SOAP notes error:', error);
        res.status(500).json({ error: 'Failed to retrieve SOAP notes' });
    }
});

// Create PT certificate
app.post('/api/pn/:id/certificate', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;
        const { certificate_type, certificate_data } = req.body;

        // Check access - ADMIN and PT only
        if (req.user.role !== 'ADMIN' && req.user.role !== 'PT') {
            return res.status(403).json({ error: 'Only ADMIN or PT can create certificates' });
        }

        if (!certificate_type || !['thai', 'english'].includes(certificate_type)) {
            return res.status(400).json({ error: 'Invalid certificate type. Must be "thai" or "english"' });
        }

        // Verify case is COMPLETED
        const [cases] = await db.execute(
            'SELECT status FROM pn_cases WHERE id = ?',
            [id]
        );

        if (cases.length === 0) {
            return res.status(404).json({ error: 'PN case not found' });
        }

        if (cases[0].status !== 'COMPLETED') {
            return res.status(400).json({ error: 'Can only create certificates for COMPLETED cases' });
        }

        // Insert certificate
        const [result] = await db.execute(
            `INSERT INTO pt_certificates (pn_id, certificate_type, certificate_data, created_by)
             VALUES (?, ?, ?, ?)`,
            [id, certificate_type, JSON.stringify(certificate_data), req.user.id]
        );

        await auditLog(db, req.user.id, 'CREATE_CERTIFICATE', 'pt_certificate', result.insertId,
                      null, { pn_id: id, certificate_type }, req);

        res.json({
            success: true,
            message: 'Certificate created successfully',
            certificate_id: result.insertId
        });
    } catch (error) {
        console.error('Create certificate error:', error);
        res.status(500).json({ error: 'Failed to create certificate' });
    }
});

// Get certificates for a PN case
app.get('/api/pn/:id/certificates', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;

        const [certificates] = await db.execute(
            `SELECT c.*, CONCAT(u.first_name, ' ', u.last_name) as created_by_name
             FROM pt_certificates c
             JOIN users u ON c.created_by = u.id
             WHERE c.pn_id = ?
             ORDER BY c.created_at DESC`,
            [id]
        );

        res.json(certificates);
    } catch (error) {
        console.error('Get certificates error:', error);
        res.status(500).json({ error: 'Failed to retrieve certificates' });
    }
});

// Get single PN case with details
app.get('/api/pn/:id', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;
        
        const [cases] = await db.execute(
            `SELECT 
                pn.*,
                p.hn, p.pt_number, p.first_name, p.last_name, p.dob, p.gender,
                p.diagnosis as patient_diagnosis, p.rehab_goal, p.precaution,
                sc.name as source_clinic_name,
                tc.name as target_clinic_name,
                CONCAT(u.first_name, ' ', u.last_name) as created_by_name,
                CONCAT(pt.first_name, ' ', pt.last_name) as assigned_pt_name
            FROM pn_cases pn
            JOIN patients p ON pn.patient_id = p.id
            JOIN clinics sc ON pn.source_clinic_id = sc.id
            JOIN clinics tc ON pn.target_clinic_id = tc.id
            JOIN users u ON pn.created_by = u.id
            LEFT JOIN users pt ON pn.assigned_pt_id = pt.id
            WHERE pn.id = ?`,
            [id]
        );
        
        if (cases.length === 0) {
            return res.status(404).json({ error: 'PN case not found' });
        }
        
        // Get visits
        const [visits] = await db.execute(
            `SELECT v.*, CONCAT(u.first_name, ' ', u.last_name) as therapist_name
             FROM pn_visits v
             LEFT JOIN users u ON v.therapist_id = u.id
             WHERE v.pn_id = ?
             ORDER BY v.visit_no`,
            [id]
        );
        
        // Get reports
        const [reports] = await db.execute(
            `SELECT r.*, v.visit_no
             FROM pn_reports r
             JOIN pn_visits v ON r.visit_id = v.id
             WHERE v.pn_id = ?
             ORDER BY r.created_at DESC`,
            [id]
        );
        
        // ******** FIX: ADDED SOAP NOTES TO RESPONSE ********
        // Get SOAP notes
        const [soap_notes] = await db.execute(
            `SELECT s.*, CONCAT(u.first_name, ' ', u.last_name) as created_by_name
             FROM pn_soap_notes s
             JOIN users u ON s.created_by = u.id
             WHERE s.pn_id = ?
             ORDER BY s.timestamp DESC`,
            [id]
        );
        
        // Get attachments
        const [attachments] = await db.execute(
            `SELECT a.*, CONCAT(u.first_name, ' ', u.last_name) as uploaded_by_name
             FROM pn_attachments a
             JOIN users u ON a.uploaded_by = u.id
             WHERE a.pn_id = ?
             ORDER BY a.created_at DESC`,
            [id]
        );
        
        res.json({
            ...cases[0],
            visits,
            reports,
            soap_notes, // Add SOAP notes to the response
            attachments // Add attachments to the response
        });
    } catch (error) {
        console.error('Get PN case error:', error);
        res.status(500).json({ error: 'Failed to retrieve PN case details' });
    }
});

// ========================================
// APPOINTMENT ROUTES (NEW)
// ========================================

// Get all appointments (with filters)
app.get('/api/appointments', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { pt_id, clinic_id, start_date, end_date, status } = req.query;

        let query = `
            SELECT
                a.*,
                p.hn, p.pt_number, p.first_name, p.last_name, p.gender, p.dob,
                CONCAT(pt.first_name, ' ', pt.last_name) as pt_name,
                c.name as clinic_name,
                CONCAT(u.first_name, ' ', u.last_name) as created_by_name
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            JOIN users pt ON a.pt_id = pt.id
            JOIN clinics c ON a.clinic_id = c.id
            JOIN users u ON a.created_by = u.id
            WHERE 1=1
        `;
        const params = [];

        // Filter by PT
        if (pt_id) {
            query += ' AND a.pt_id = ?';
            params.push(pt_id);
        }

        // Filter by Clinic
        if (clinic_id) {
            query += ' AND a.clinic_id = ?';
            params.push(clinic_id);
        }

        // Filter by date range
        if (start_date) {
            query += ' AND a.appointment_date >= ?';
            params.push(start_date);
        }
        if (end_date) {
            query += ' AND a.appointment_date <= ?';
            params.push(end_date);
        }

        // Filter by status
        if (status) {
            query += ' AND a.status = ?';
            params.push(status);
        }

        query += ' ORDER BY a.appointment_date, a.start_time';

        const [appointments] = await db.execute(query, params);

        res.json(appointments);
    } catch (error) {
        console.error('Get appointments error:', error);
        res.status(500).json({ error: 'Failed to retrieve appointments' });
    }
});

// Check for appointment conflicts
app.post('/api/appointments/check-conflict', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { pt_id, appointment_date, start_time, end_time, exclude_appointment_id } = req.body;

        if (!pt_id || !appointment_date || !start_time || !end_time) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        let query = `
            SELECT id, start_time, end_time,
                   CONCAT(p.first_name, ' ', p.last_name) as patient_name
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            WHERE a.pt_id = ?
              AND a.appointment_date = ?
              AND a.status != 'CANCELLED'
              AND (
                  (a.start_time < ? AND a.end_time > ?) OR
                  (a.start_time < ? AND a.end_time > ?) OR
                  (a.start_time >= ? AND a.end_time <= ?)
              )
        `;
        const params = [pt_id, appointment_date, end_time, start_time, end_time, start_time, start_time, end_time];

        // Exclude current appointment when rescheduling
        if (exclude_appointment_id) {
            query += ' AND a.id != ?';
            params.push(exclude_appointment_id);
        }

        const [conflicts] = await db.execute(query, params);

        res.json({
            hasConflict: conflicts.length > 0,
            conflicts: conflicts
        });
    } catch (error) {
        console.error('Check conflict error:', error);
        res.status(500).json({ error: 'Failed to check conflicts' });
    }
});

// Create new appointment
app.post('/api/appointments', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const {
            patient_id,
            pt_id,
            clinic_id,
            appointment_date,
            start_time,
            end_time,
            appointment_type,
            reason,
            notes
        } = req.body;

        // Check access - Only ADMIN and PT can create appointments
        if (req.user.role !== 'ADMIN' && req.user.role !== 'PT') {
            return res.status(403).json({ error: 'Only ADMIN or PT can create appointments' });
        }

        // Validate required fields
        if (!patient_id || !pt_id || !clinic_id || !appointment_date || !start_time || !end_time) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Check for conflicts
        const [conflicts] = await db.execute(
            `SELECT id FROM appointments
             WHERE pt_id = ? AND appointment_date = ? AND status != 'CANCELLED'
               AND (
                   (start_time < ? AND end_time > ?) OR
                   (start_time < ? AND end_time > ?) OR
                   (start_time >= ? AND end_time <= ?)
               )`,
            [pt_id, appointment_date, end_time, start_time, end_time, start_time, start_time, end_time]
        );

        if (conflicts.length > 0) {
            return res.status(409).json({ error: 'Time slot conflict detected' });
        }

        // Create appointment
        const [result] = await db.execute(
            `INSERT INTO appointments
             (patient_id, pt_id, clinic_id, appointment_date, start_time, end_time,
              appointment_type, reason, notes, created_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [patient_id, pt_id, clinic_id, appointment_date, start_time, end_time,
             appointment_type, reason, notes, req.user.id]
        );

        // Get created appointment details
        const [appointments] = await db.execute(
            `SELECT a.*,
                    p.hn, CONCAT(p.first_name, ' ', p.last_name) as patient_name,
                    CONCAT(pt.first_name, ' ', pt.last_name) as pt_name,
                    c.name as clinic_name
             FROM appointments a
             JOIN patients p ON a.patient_id = p.id
             JOIN users pt ON a.pt_id = pt.id
             JOIN clinics c ON a.clinic_id = c.id
             WHERE a.id = ?`,
            [result.insertId]
        );

        res.status(201).json(appointments[0]);
    } catch (error) {
        console.error('Create appointment error:', error);
        res.status(500).json({ error: 'Failed to create appointment' });
    }
});

// Update/Reschedule appointment
app.put('/api/appointments/:id', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;
        const {
            appointment_date,
            start_time,
            end_time,
            status,
            appointment_type,
            reason,
            notes
        } = req.body;

        // Check access
        if (req.user.role !== 'ADMIN' && req.user.role !== 'PT') {
            return res.status(403).json({ error: 'Only ADMIN or PT can update appointments' });
        }

        // Get current appointment
        const [appointments] = await db.execute(
            'SELECT * FROM appointments WHERE id = ?',
            [id]
        );

        if (appointments.length === 0) {
            return res.status(404).json({ error: 'Appointment not found' });
        }

        const appointment = appointments[0];

        // Check for conflicts if rescheduling
        if (appointment_date && start_time && end_time) {
            const [conflicts] = await db.execute(
                `SELECT id FROM appointments
                 WHERE pt_id = ? AND appointment_date = ? AND status != 'CANCELLED' AND id != ?
                   AND (
                       (start_time < ? AND end_time > ?) OR
                       (start_time < ? AND end_time > ?) OR
                       (start_time >= ? AND end_time <= ?)
                   )`,
                [appointment.pt_id, appointment_date, id, end_time, start_time, end_time, start_time, start_time, end_time]
            );

            if (conflicts.length > 0) {
                return res.status(409).json({ error: 'Time slot conflict detected' });
            }
        }

        // Build update query
        const updates = [];
        const params = [];

        if (appointment_date) {
            updates.push('appointment_date = ?');
            params.push(appointment_date);
        }
        if (start_time) {
            updates.push('start_time = ?');
            params.push(start_time);
        }
        if (end_time) {
            updates.push('end_time = ?');
            params.push(end_time);
        }
        if (status) {
            updates.push('status = ?');
            params.push(status);
        }
        if (appointment_type !== undefined) {
            updates.push('appointment_type = ?');
            params.push(appointment_type);
        }
        if (reason !== undefined) {
            updates.push('reason = ?');
            params.push(reason);
        }
        if (notes !== undefined) {
            updates.push('notes = ?');
            params.push(notes);
        }

        if (updates.length === 0) {
            return res.status(400).json({ error: 'No fields to update' });
        }

        params.push(id);

        await db.execute(
            `UPDATE appointments SET ${updates.join(', ')}, updated_at = NOW() WHERE id = ?`,
            params
        );

        // Get updated appointment
        const [updated] = await db.execute(
            `SELECT a.*,
                    p.hn, CONCAT(p.first_name, ' ', p.last_name) as patient_name,
                    CONCAT(pt.first_name, ' ', pt.last_name) as pt_name,
                    c.name as clinic_name
             FROM appointments a
             JOIN patients p ON a.patient_id = p.id
             JOIN users pt ON a.pt_id = pt.id
             JOIN clinics c ON a.clinic_id = c.id
             WHERE a.id = ?`,
            [id]
        );

        res.json(updated[0]);
    } catch (error) {
        console.error('Update appointment error:', error);
        res.status(500).json({ error: 'Failed to update appointment' });
    }
});

// Cancel appointment
app.delete('/api/appointments/:id', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;
        const { cancellation_reason } = req.body;

        // Check access
        if (req.user.role !== 'ADMIN' && req.user.role !== 'PT') {
            return res.status(403).json({ error: 'Only ADMIN or PT can cancel appointments' });
        }

        await db.execute(
            `UPDATE appointments
             SET status = 'CANCELLED',
                 cancellation_reason = ?,
                 cancelled_at = NOW(),
                 cancelled_by = ?,
                 updated_at = NOW()
             WHERE id = ?`,
            [cancellation_reason || '', req.user.id, id]
        );

        res.json({ message: 'Appointment cancelled successfully' });
    } catch (error) {
        console.error('Cancel appointment error:', error);
        res.status(500).json({ error: 'Failed to cancel appointment' });
    }
});

// ========================================
// ATTACHMENT ROUTES (NEW)
// ========================================

// Upload attachment
app.post('/api/pn/:id/upload', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        const db = req.app.locals.db;
        const pnId = req.params.id;
        const file = req.file;
        const userId = req.user.id;

        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Save to database
        const [result] = await db.execute(
            `INSERT INTO pn_attachments (pn_id, file_name, file_path, mime_type, file_size, uploaded_by)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [pnId, file.originalname, file.path, file.mimetype, file.size, userId]
        );
        
        await auditLog(db, userId, 'UPLOAD_ATTACHMENT', 'pn_attachment', result.insertId, null, file, req);
        
        // Get the newly created attachment to send back
        const [newAttachment] = await db.execute(
            `SELECT a.*, CONCAT(u.first_name, ' ', u.last_name) as uploaded_by_name
             FROM pn_attachments a
             JOIN users u ON a.uploaded_by = u.id
             WHERE a.id = ?`,
            [result.insertId]
        );

        res.status(201).json({
            success: true,
            message: 'File uploaded successfully',
            attachment: newAttachment[0]
        });

    } catch (error) {
        console.error('Upload attachment error:', error);
        res.status(500).json({ error: 'Failed to upload file' });
    }
});

// Download attachment
app.get('/api/attachment/:id/download', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;

        const [attachments] = await db.execute(
            'SELECT * FROM pn_attachments WHERE id = ?',
            [id]
        );

        if (attachments.length === 0) {
            return res.status(404).json({ error: 'Attachment not found' });
        }

        const attachment = attachments[0];

        // Check file exists
        try {
            await fs.promises.access(attachment.file_path);
            res.download(attachment.file_path, attachment.file_name);
        } catch {
            return res.status(404).json({ error: 'File not found on server' });
        }

    } catch (error) {
        console.error('Download attachment error:', error);
        res.status(500).json({ error: 'Failed to download file' });
    }
});

// Delete attachment
app.delete('/api/attachment/:id', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;

        // Get attachment details
        const [attachments] = await db.execute(
            'SELECT * FROM pn_attachments WHERE id = ?',
            [id]
        );

        if (attachments.length === 0) {
            return res.status(404).json({ error: 'Attachment not found' });
        }
        
        const attachment = attachments[0];
        
        // ******** PERMISSION CHANGE ********
        // Check permissions (Admin, PT, or PT_ADMIN can delete)
        const allowedRoles = ['ADMIN', 'PT', 'PT_ADMIN'];
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ error: 'You do not have permission to delete this file' });
        }

        // Delete file from disk
        try {
            await fs.promises.unlink(attachment.file_path);
        } catch (err) {
            console.error(`Failed to delete file from disk: ${attachment.file_path}`, err);
            // Don't stop the process, just log it. We still want to remove the DB_ entry.
        }

        // Delete from database
        await db.execute('DELETE FROM pn_attachments WHERE id = ?', [id]);
        
        await auditLog(db, req.user.id, 'DELETE_ATTACHMENT', 'pn_attachment', id, attachment, null, req);

        res.json({ success: true, message: 'Attachment deleted successfully' });

    } catch (error) {
        console.error('Delete attachment error:', error);
        res.status(500).json({ error: 'Failed to delete attachment' });
    }
});


// ========================================
// VISITS AND REPORTS ROUTES
// ========================================

// Create visit
app.post('/api/pn/:id/visit', authenticateToken, [
    body('visit_date').isDate(),
    body('status').isIn(['SCHEDULED', 'COMPLETED', 'CANCELLED', 'NO_SHOW'])
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        const db = req.app.locals.db;
        const pnId = req.params.id;
        
        // Get next visit number
        const [maxVisit] = await db.execute(
            'SELECT MAX(visit_no) as max_no FROM pn_visits WHERE pn_id = ?',
            [pnId]
        );
        
        const visitNo = (maxVisit[0].max_no || 0) + 1;
        
        const [result] = await db.execute(
            `INSERT INTO pn_visits (
                pn_id, visit_no, visit_date, visit_time, status,
                chief_complaint, subjective, objective, assessment, plan,
                treatment_provided, therapist_id, duration_minutes, notes, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                pnId, visitNo, req.body.visit_date, req.body.visit_time || null,
                req.body.status || 'SCHEDULED',
                req.body.chief_complaint || null, req.body.subjective || null,
                req.body.objective || null, req.body.assessment || null,
                req.body.plan || null, req.body.treatment_provided || null,
                req.body.therapist_id || req.user.id, req.body.duration_minutes || null,
                req.body.notes || null, req.user.id
            ]
        );
        
        await auditLog(db, req.user.id, 'CREATE', 'visit', result.insertId, null, req.body, req);
        
        res.status(201).json({
            success: true,
            message: 'Visit created successfully',
            visit_id: result.insertId,
            visit_no: visitNo
        });
    } catch (error) {
        console.error('Create visit error:', error);
        res.status(500).json({ error: 'Failed to create visit' });
    }
});

// Generate and save report
app.post('/api/visit/:id/report', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const visitId = req.params.id;
        
        // Get visit and case details
        const [visits] = await db.execute(
            `SELECT v.*, pn.pn_code, pn.diagnosis, pn.purpose,
                    p.hn, p.pt_number, p.first_name, p.last_name, p.dob,
                    c.name as clinic_name, c.address as clinic_address
             FROM pn_visits v
             JOIN pn_cases pn ON v.pn_id = pn.id
             JOIN patients p ON pn.patient_id = p.id
             JOIN clinics c ON pn.target_clinic_id = c.id
             WHERE v.id = ?`,
            [visitId]
        );
        
        if (visits.length === 0) {
            return res.status(404).json({ error: 'Visit not found' });
        }
        
        const visit = visits[0];
        const fileName = `report_${visit.pn_code}_visit${visit.visit_no}_${Date.now()}.pdf`;
        const filePath = path.join(process.env.REPORTS_DIR || './reports', fileName);
        
        // Create PDF
        const doc = new PDFDocument();
        const writeStream = require('fs').createWriteStream(filePath);
        const stream = doc.pipe(writeStream);
        
        // Header
        doc.fontSize(20).text('Physiotherapy Report', { align: 'center' });
        doc.moveDown();
        doc.fontSize(14).text(visit.clinic_name, { align: 'center' });
        doc.fontSize(10).text(visit.clinic_address || '', { align: 'center' });
        doc.moveDown();
        
        // Report info
        doc.fontSize(12);
        doc.text(`Report Date: ${moment().format('DD/MM/YYYY HH:mm')}`);
        doc.text(`PN Code: ${visit.pn_code}`);
        doc.text(`Visit No: ${visit.visit_no}`);
        doc.moveDown();
        
        // Patient info
        doc.fontSize(14).text('Patient Information', { underline: true });
        doc.fontSize(11);
        doc.text(`HN: ${visit.hn}`);
        doc.text(`PT Number: ${visit.pt_number}`);
        doc.text(`Name: ${visit.first_name} ${visit.last_name}`);
        doc.text(`DOB: ${moment(visit.dob).format('DD/MM/YYYY')}`);
        doc.text(`Diagnosis: ${visit.diagnosis}`);
        doc.moveDown();
        
        // Visit details
        doc.fontSize(14).text('Visit Details', { underline: true });
        doc.fontSize(11);
        doc.text(`Visit Date: ${moment(visit.visit_date).format('DD/MM/YYYY')}`);
        doc.text(`Status: ${visit.status}`);
        
        if (visit.chief_complaint) {
            doc.moveDown();
            doc.text('Chief Complaint:', { underline: true });
            doc.text(visit.chief_complaint);
        }
        
        if (visit.subjective) {
            doc.moveDown();
            doc.text('Subjective:', { underline: true });
            doc.text(visit.subjective);
        }
        
        if (visit.objective) {
            doc.moveDown();
            doc.text('Objective:', { underline: true });
            doc.text(visit.objective);
        }
        
        if (visit.assessment) {
            doc.moveDown();
            doc.text('Assessment:', { underline: true });
            doc.text(visit.assessment);
        }
        
        if (visit.plan) {
            doc.moveDown();
            doc.text('Plan:', { underline: true });
            doc.text(visit.plan);
        }
        
        if (visit.treatment_provided) {
            doc.moveDown();
            doc.text('Treatment Provided:', { underline: true });
            doc.text(visit.treatment_provided);
        }
        
        // Generate QR code for download link
        const downloadUrl = `${process.env.APP_BASE_URL}/api/report/${visitId}/download`;
        const qrCode = await QRCode.toDataURL(downloadUrl);
        
        // Add QR code to PDF
        doc.moveDown();
        doc.text('Scan QR code to download this report:', { align: 'center' });
        doc.image(qrCode, doc.page.width / 2 - 50, doc.y + 10, { width: 100 });
        
        // Footer
        doc.fontSize(10);
        doc.text(`Generated on ${moment().format('DD/MM/YYYY HH:mm:ss')}`, 
                50, doc.page.height - 50, { align: 'center' });
        
        doc.end();
        
        // Wait for PDF to be written
        await new Promise((resolve) => stream.on('finish', resolve));
        
        // Save report record to database
        const [result] = await db.execute(
            `INSERT INTO pn_reports (
                visit_id, report_type, file_path, file_name, 
                mime_type, file_size, qr_code, report_data, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                visitId,
                req.body.report_type || 'PROGRESS',
                filePath,
                fileName,
                'application/pdf',
                (await require('fs').promises.stat(filePath)).size,
                qrCode,
                JSON.stringify(visit),
                req.user.id
            ]
        );
        
        await auditLog(db, req.user.id, 'CREATE', 'report', result.insertId, null, 
                      { visit_id: visitId }, req);
        
        res.json({
            success: true,
            message: 'Report generated successfully',
            report_id: result.insertId,
            download_url: `/api/report/${result.insertId}/download`
        });
    } catch (error) {
        console.error('Generate report error:', error);
        res.status(500).json({ error: 'Failed to generate report' });
    }
});

// Download report
app.get('/api/report/:id/download', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;
        
        const [reports] = await db.execute(
            'SELECT * FROM pn_reports WHERE id = ?',
            [id]
        );
        
        if (reports.length === 0) {
            return res.status(404).json({ error: 'Report not found' });
        }
        
        const report = reports[0];
        
        // Check if file exists
        try {
            await require('fs').promises.access(report.file_path);
        } catch {
            return res.status(404).json({ error: 'Report file not found' });
        }
        
        res.download(report.file_path, report.file_name);
    } catch (error) {
        console.error('Download report error:', error);
        res.status(500).json({ error: 'Failed to download report' });
    }
});

// ========================================
// CLINIC MANAGEMENT ROUTES
// ========================================

// Get clinics
app.get('/api/clinics', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        let query = 'SELECT * FROM clinics WHERE active = 1';
        const params = [];
        
        // If not admin, only show accessible clinics
        if (req.user.role !== 'ADMIN') {
            const [grants] = await db.execute(
                'SELECT clinic_id FROM user_clinic_grants WHERE user_id = ? UNION SELECT ? as clinic_id WHERE ? IS NOT NULL',
                [req.user.id, req.user.clinic_id, req.user.clinic_id]
            );
            
            if (grants.length > 0) {
                const clinicIds = grants.map(g => g.clinic_id).filter(id => id);
                query += ` AND id IN (${clinicIds.map(() => '?').join(',')})`;
                params.push(...clinicIds);
            }
        }
        
        query += ' ORDER BY name';
        
        const [clinics] = await db.execute(query, params);
        res.json(clinics);
    } catch (error) {
        console.error('Get clinics error:', error);
        res.status(500).json({ error: 'Failed to retrieve clinics' });
    }
});

// Get users by role (for appointments, etc.)
app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { role } = req.query;

        let query = 'SELECT id, email, first_name, last_name, role, clinic_id FROM users WHERE active = 1';
        const params = [];

        // Filter by role if provided
        if (role) {
            query += ' AND role = ?';
            params.push(role);
        }

        query += ' ORDER BY first_name, last_name';

        const [users] = await db.execute(query, params);
        res.json(users);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to retrieve users' });
    }
});

// ========================================
// ADMIN ROUTES
// ========================================

// Get all users (Admin only)
app.get('/api/admin/users', authenticateToken, authorize('ADMIN'), async (req, res) => {
    try {
        const db = req.app.locals.db;
        
        const [users] = await db.execute(
            `SELECT u.*, c.name as clinic_name
             FROM users u
             LEFT JOIN clinics c ON u.clinic_id = c.id
             ORDER BY u.created_at DESC`
        );
        
        res.json(users);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to retrieve users' });
    }
});

// Create user (Admin only)
app.post('/api/admin/users', authenticateToken, authorize('ADMIN'), async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { email, password, role, first_name, last_name, clinic_id, phone, license_number } = req.body;
        
        // Check if email exists
        const [existing] = await db.execute(
            'SELECT id FROM users WHERE email = ?',
            [email]
        );
        
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Email already exists' });
        }
        
        const hashedPassword = await hashPassword(password);
        
        const [result] = await db.execute(
            `INSERT INTO users (email, password_hash, role, first_name, last_name, clinic_id, phone, license_number, active)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [email, hashedPassword, role, first_name, last_name, clinic_id, phone, license_number, true]
        );
        
        await auditLog(db, req.user.id, 'CREATE', 'user', result.insertId, null, req.body, req);
        
        res.status(201).json({ success: true, user_id: result.insertId });
    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({ error: 'Failed to create user' });
    }
});

// Update user (Admin only)
app.put('/api/admin/users/:id', authenticateToken, authorize('ADMIN'), async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;
        const { first_name, last_name, role, clinic_id, phone, license_number, active, password } = req.body;
        
        const updateFields = [];
        const updateValues = [];
        
        if (first_name !== undefined) {
            updateFields.push('first_name = ?');
            updateValues.push(first_name);
        }
        if (last_name !== undefined) {
            updateFields.push('last_name = ?');
            updateValues.push(last_name);
        }
        if (role !== undefined) {
            updateFields.push('role = ?');
            updateValues.push(role);
        }
        if (clinic_id !== undefined) {
            updateFields.push('clinic_id = ?');
            updateValues.push(clinic_id);
        }
        if (phone !== undefined) {
            updateFields.push('phone = ?');
            updateValues.push(phone);
        }
        if (license_number !== undefined) {
            updateFields.push('license_number = ?');
            updateValues.push(license_number);
        }
        if (active !== undefined) {
            updateFields.push('active = ?');
            updateValues.push(active);
        }
        if (password) {
            const hashedPassword = await hashPassword(password);
            updateFields.push('password_hash = ?');
            updateValues.push(hashedPassword);
        }
        
        if (updateFields.length === 0) {
            return res.status(400).json({ error: 'No fields to update' });
        }
        
        updateFields.push('updated_at = NOW()');
        updateValues.push(id);
        
        await db.execute(
            `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`,
            updateValues
        );
        
        await auditLog(db, req.user.id, 'UPDATE', 'user', id, null, req.body, req);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

// Toggle user status (Admin only)
app.patch('/api/admin/users/:id/status', authenticateToken, authorize('ADMIN'), async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;
        const { active } = req.body;
        
        await db.execute(
            'UPDATE users SET active = ?, updated_at = NOW() WHERE id = ?',
            [active, id]
        );
        
        await auditLog(db, req.user.id, 'UPDATE_STATUS', 'user', id, null, { active }, req);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Toggle user status error:', error);
        res.status(500).json({ error: 'Failed to update user status' });
    }
});

// Get user clinic grants
app.get('/api/admin/users/:id/grants', authenticateToken, authorize('ADMIN'), async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;
        
        const [grants] = await db.execute(
            `SELECT g.*, c.name as clinic_name
             FROM user_clinic_grants g
             JOIN clinics c ON g.clinic_id = c.id
             WHERE g.user_id = ?`,
            [id]
        );
        
        res.json(grants);
    } catch (error) {
        console.error('Get user grants error:', error);
        res.status(500).json({ error: 'Failed to retrieve grants' });
    }
});

// Add clinic grant
app.post('/api/admin/grants', authenticateToken, authorize('ADMIN'), async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { user_id, clinic_id } = req.body;
        
        // Check if grant already exists
        const [existing] = await db.execute(
            'SELECT id FROM user_clinic_grants WHERE user_id = ? AND clinic_id = ?',
            [user_id, clinic_id]
        );
        
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Grant already exists' });
        }
        
        await db.execute(
            'INSERT INTO user_clinic_grants (user_id, clinic_id, granted_by) VALUES (?, ?, ?)',
            [user_id, clinic_id, req.user.id]
        );
        
        await auditLog(db, req.user.id, 'CREATE', 'grant', null, null, { user_id, clinic_id }, req);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Add grant error:', error);
        res.status(500).json({ error: 'Failed to add grant' });
    }
});

// Remove clinic grant
app.delete('/api/admin/grants/:userId/:clinicId', authenticateToken, authorize('ADMIN'), async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { userId, clinicId } = req.params;
        
        await db.execute(
            'DELETE FROM user_clinic_grants WHERE user_id = ? AND clinic_id = ?',
            [userId, clinicId]
        );
        
        await auditLog(db, req.user.id, 'DELETE', 'grant', null, { user_id: userId, clinic_id: clinicId }, null, req);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Remove grant error:', error);
        res.status(500).json({ error: 'Failed to remove grant' });
    }
});

// Get all clinics with statistics (Admin only)
app.get('/api/admin/clinics', authenticateToken, authorize('ADMIN'), async (req, res) => {
    try {
        const db = req.app.locals.db;
        
        const [clinics] = await db.execute(
            `SELECT c.*,
                    (SELECT COUNT(*) FROM patients WHERE clinic_id = c.id) as patient_count,
                    (SELECT COUNT(*) FROM pn_cases WHERE source_clinic_id = c.id OR target_clinic_id = c.id) as case_count,
                    (SELECT COUNT(*) FROM users WHERE clinic_id = c.id AND active = 1) as user_count
             FROM clinics c
             ORDER BY c.name`
        );
        
        const [stats] = await db.execute(
            `SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END) as active,
                (SELECT COUNT(*) FROM patients) as total_patients,
                (SELECT COUNT(*) FROM pn_cases) as total_cases
             FROM clinics`
        );
        
        res.json({
            clinics,
            statistics: stats[0]
        });
    } catch (error) {
        console.error('Get clinics error:', error);
        res.status(500).json({ error: 'Failed to retrieve clinics' });
    }
});

// Create clinic (Admin only)
app.post('/api/admin/clinics', authenticateToken, authorize('ADMIN'), async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { code, name, address, phone, email, contact_person } = req.body;
        
        // Check if code exists
        const [existing] = await db.execute(
            'SELECT id FROM clinics WHERE code = ?',
            [code]
        );
        
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Clinic code already exists' });
        }
        
        const [result] = await db.execute(
            `INSERT INTO clinics (code, name, address, phone, email, contact_person, active)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [code, name, address, phone, email, contact_person, true]
        );
        
        await auditLog(db, req.user.id, 'CREATE', 'clinic', result.insertId, null, req.body, req);
        
        res.status(201).json({ success: true, clinic_id: result.insertId });
    } catch (error) {
        console.error('Create clinic error:', error);
        res.status(500).json({ error: 'Failed to create clinic' });
    }
});

// Update clinic (Admin only)
app.put('/api/admin/clinics/:id', authenticateToken, authorize('ADMIN'), async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;
        const { code, name, address, phone, email, contact_person, active } = req.body;
        
        const updateFields = [];
        const updateValues = [];
        
        if (code !== undefined) {
            updateFields.push('code = ?');
            updateValues.push(code);
        }
        if (name !== undefined) {
            updateFields.push('name = ?');
            updateValues.push(name);
        }
        if (address !== undefined) {
            updateFields.push('address = ?');
            updateValues.push(address);
        }
        if (phone !== undefined) {
            updateFields.push('phone = ?');
            updateValues.push(phone);
        }
        if (email !== undefined) {
            updateFields.push('email = ?');
            updateValues.push(email);
        }
        if (contact_person !== undefined) {
            updateFields.push('contact_person = ?');
            updateValues.push(contact_person);
        }
        if (active !== undefined) {
            updateFields.push('active = ?');
            updateValues.push(active);
        }
        
        if (updateFields.length === 0) {
            return res.status(400).json({ error: 'No fields to update' });
        }
        
        updateFields.push('updated_at = NOW()');
        updateValues.push(id);
        
        await db.execute(
            `UPDATE clinics SET ${updateFields.join(', ')} WHERE id = ?`,
            updateValues
        );
        
        await auditLog(db, req.user.id, 'UPDATE', 'clinic', id, null, req.body, req);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Update clinic error:', error);
        res.status(500).json({ error: 'Failed to update clinic' });
    }
});

// Toggle clinic status (Admin only)
app.patch('/api/admin/clinics/:id/status', authenticateToken, authorize('ADMIN'), async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;
        const { active } = req.body;
        
        await db.execute(
            'UPDATE clinics SET active = ?, updated_at = NOW() WHERE id = ?',
            [active, id]
        );
        
        await auditLog(db, req.user.id, 'UPDATE_STATUS', 'clinic', id, null, { active }, req);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Toggle clinic status error:', error);
        res.status(500).json({ error: 'Failed to update clinic status' });
    }
});

// Get clinic details (Admin only)
app.get('/api/admin/clinics/:id/details', authenticateToken, authorize('ADMIN'), async (req, res) => {
    try {
        const db = req.app.locals.db;
        const { id } = req.params;
        
        const [clinic] = await db.execute(
            'SELECT * FROM clinics WHERE id = ?',
            [id]
        );
        
        if (clinic.length === 0) {
            return res.status(404).json({ error: 'Clinic not found' });
        }
        
        const [stats] = await db.execute(
            `SELECT 
                (SELECT COUNT(*) FROM patients WHERE clinic_id = ?) as patient_count,
                (SELECT COUNT(*) FROM pn_cases WHERE source_clinic_id = ? OR target_clinic_id = ?) as case_count,
                (SELECT COUNT(*) FROM users WHERE clinic_id = ? AND active = 1) as user_count`,
            [id, id, id, id]
        );
        
        const [recentCases] = await db.execute(
            `SELECT pn.pn_code, pn.status, pn.created_at,
                    CONCAT(p.first_name, ' ', p.last_name) as patient_name
             FROM pn_cases pn
             JOIN patients p ON pn.patient_id = p.id
             WHERE pn.source_clinic_id = ? OR pn.target_clinic_id = ?
             ORDER BY pn.created_at DESC
             LIMIT 5`,
            [id, id]
        );
        
        res.json({
            ...clinic[0],
            ...stats[0],
            recent_cases: recentCases
        });
    } catch (error) {
        console.error('Get clinic details error:', error);
        res.status(500).json({ error: 'Failed to retrieve clinic details' });
    }
});

// ========================================
// WEB PAGE ROUTES (Views)
// ========================================

// Login page
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

// Dashboard
app.get('/', authenticateToken, (req, res) => {
    res.render('dashboard', { user: req.user });
});

app.get('/dashboard', authenticateToken, (req, res) => {
    res.render('dashboard', { user: req.user });
});

// Appointments page (PT and ADMIN only)
app.get('/appointments', authenticateToken, (req, res) => {
    if (req.user.role !== 'ADMIN' && req.user.role !== 'PT') {
        return res.status(403).send('Access denied. Only ADMIN or PT can access appointments.');
    }
    res.render('appointments', { user: req.user });
});

// Patients page
app.get('/patients', authenticateToken, (req, res) => {
    res.render('patients', { user: req.user });
});

// Patient registration
app.get('/patient/register', authenticateToken, (req, res) => {
    res.render('patient-register', { user: req.user });
});

// Patient detail
app.get('/patient/:id', authenticateToken, (req, res) => {
    res.render('patient-detail', { user: req.user, patientId: req.params.id });
});

// PN case detail
app.get('/pn/:id', authenticateToken, (req, res) => {
    res.render('pn-detail', { user: req.user, pnId: req.params.id });
});

// Profile page
app.get('/profile', authenticateToken, (req, res) => {
    res.render('profile', { user: req.user });
});

// Diagnostic page (for troubleshooting)
app.get('/diagnostic', authenticateToken, (req, res) => {
    res.render('diagnostic', { user: req.user });
});

// Test static files
app.get('/test-static', authenticateToken, (req, res) => {
    res.render('test-static', { user: req.user });
});

// Admin pages
app.get('/admin/users', authenticateToken, authorize('ADMIN'), (req, res) => {
    res.render('admin/users', { user: req.user });
});

app.get('/admin/clinics', authenticateToken, authorize('ADMIN'), (req, res) => {
    res.render('admin/clinics', { user: req.user });
});

module.exports = app;