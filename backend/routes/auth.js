const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { getStaffByEmail } = require('../models/Staff');

router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) return res.status(400).json({ message: 'Campos obrigatórios' });

    try {
        const staff = await getStaffByEmail(email);
        if (!staff) return res.status(401).json({ message: 'Email ou password incorretos' });

        const match = await bcrypt.compare(password, staff.password);
        if (!match) return res.status(401).json({ message: 'Email ou password incorretos' });

        req.session.staff = {
            id: staff.id,
            name: staff.name,
            role: staff.role
        };

        res.json({ success: true, name: staff.name, role: staff.role });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Erro interno' });
    }
});

router.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

module.exports = router;
