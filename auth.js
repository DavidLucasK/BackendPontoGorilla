const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');

const router = express.Router();

const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage, 
    limits: { fileSize: 10 * 1024 * 1024 } // Limite de 10MB
});

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Configura o transporte de e-mail
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD,
    },
});

// Endpoint para registro
router.post('/register', async (req, res) => {
    const { email, password } = req.body;

    try {
        const { data: existingUser, error: existingUserError } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (existingUserError && existingUserError.code !== 'PGRST116') {
            throw existingUserError;
        }

        if (existingUser) {
            return res.status(400).json({ message: 'Usuário já existe' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const { data, error } = await supabase
            .from('users')
            .insert([{ email, password: hashedPassword }]);

        if (error) {
            throw error;
        }

        res.status(201).json({ message: 'Conta criada com sucesso!' });
    } catch (err) {
        console.error('Erro ao registrar o usuário:', err);
        res.status(500).json({ message: 'Erro no servidor' });
    }
});

// Endpoint para login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
    }

    try {
        // Buscar o usuário no banco de dados
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (error) {
            // Não encontrado
            if (error.code === 'PGRST116') {
                return res.status(400).json({ message: `Email não cadastrado` });
            }
            throw error;
        }

        if (!user) {
            return res.status(400).json({ message: `Usuário ${email} não existe!` });
        }

        // Comparar a senha fornecida com a armazenada
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ message: `Senha incorreta.` });
        }

        // Gerar o token JWT
        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ token, userId: user.id, message: 'Login bem-sucedido!' });
    } catch (err) {
        console.error('Erro ao fazer login:', err);
        res.status(500).json({ message: 'Erro no servidor' });
    }
});

// Endpoint para solicitar redefinição de senha
router.post('/forgot', async (req, res) => {
    const { email } = req.body;

    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {
            return res.status(400).json({ message: 'Usuário não encontrado' });
        }

        const token = crypto.randomBytes(32).toString('hex');
        const now = new Date();
        const expiresAt = new Date(now.getTime() + 15 * 60 * 1000); // Expira em 15 minutos

        // Inserir o token e a data de expiração diretamente
        const { error: insertError } = await supabase
            .from('password_resets')
            .insert([{ email, token, created_at: now, expires_at: expiresAt }]);

        if (insertError) {
            throw insertError;
        }

        const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: 'Redefinição de Senha',
            text: `Você solicitou a redefinição de senha da sua conta. Clique no link para redefinir`,
            html: `
                <div style="font-family: Arial, sans-serif; background-color: #ffffff; padding: 20px;">
                    <div style="max-width: 600px; margin: 100px auto; background-color: #343a40; padding: 100px 20px; border-radius: 8px; text-align: center;">
                        <img src="https://rrwdhhqxjjtyrgdzdsgr.supabase.co/storage/v1/object/public/assets/nome_gorilla_white.png" alt="Logo" style="max-width: 100px; margin-bottom: 20px;">
                        <h2 style="color: #ffffff;">Redefinição de Senha</h2>
                        <p style="color: #ffffff;">Você solicitou a redefinição de senha da sua conta.</p>
                        <p style="color: #ffffff;">Clique no botão abaixo para redefinir sua senha:</p>
                        <a href="${process.env.FRONTEND_URL}/index.html?token=${token}&email=${email}" style="background-color: #509e2f; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Redefinir Senha</a>
                        <p style="color: #ffffff; margin-top: 20px;">Se você não solicitou esta alteração, por favor ignore este e-mail.</p>
                    </div>
                </div>
            `
        };         

        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                console.error('Erro ao enviar e-mail:', err);
                return res.status(500).json({ message: 'Erro ao enviar e-mail!' });
            } else {
                console.log('E-mail enviado:', info.response);
                return res.status(200).json({ message: 'E-mail enviado com sucesso!' });
            }
        });
    } catch (err) {
        console.error('Erro ao solicitar redefinição de senha:', err);
        res.status(500).json({ message: 'Erro no servidor' });
    }
});

// Endpoint para redefinir a senha
router.post('/reset', async (req, res) => {
    const { email, token, newPassword } = req.body;

    console.log('Requisição recebida para redefinir senha');
    console.log('Email:', email);
    console.log('Token:', token);
    console.log('Nova Senha:', newPassword);

    if (!email || !token || !newPassword) {
        console.log('Dados incompletos na requisição');
        return res.status(400).json({ message: 'Dados incompletos' });
    }

    try {
        // Verificar o token
        const { data: resetRequest, error: resetError } = await supabase
            .from('password_resets')
            .select('*')
            .eq('email', email)
            .eq('token', token)
            .order('created_at', { ascending: false })
            .limit(1)
            .single();

        if (resetError || !resetRequest) {
            console.log('Dados retornados da consulta de redefinição de senha:', resetRequest);
            console.log('Erro na consulta de redefinição de senha:', resetError);
            return res.status(400).json({ message: 'Token inválido ou expirado' });
        }

        // Verificar se o token expirou
        const expiresAt = new Date(resetRequest.expires_at);
        if (new Date() > expiresAt) {
            return res.status(400).json({ message: 'Token expirado' });
        }

        // Atualizar a senha
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const { error: updateError } = await supabase
            .from('users')
            .update({ password: hashedPassword })
            .eq('email', email);

        if (updateError) {
            throw updateError;
        }

        // Remover o token após a redefinição da senha
        const { error: deleteError } = await supabase
            .from('password_resets')
            .delete()
            .eq('email', email)
            .eq('token', token);

        if (deleteError) {
            throw deleteError;
        }

        res.status(200).json({ message: 'Senha redefinida com sucesso' });
    } catch (err) {
        console.error('Erro ao redefinir senha:', err);
        res.status(500).json({ message: 'Erro no servidor' });
    }
});

// Endpoint para pegar infos do usuario com base no userId
router.get('/get-profile/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        // Busca os dados na tabela profile_infos com base no userId
        const { data, error } = await supabase
            .from('users_info')
            .select('*')
            .eq('id', userId)
            .single();

        if (error) {
            throw error;
        }

        if (!data) {
            return res.status(404).json({ message: 'Perfil não encontrado.' });
        }

        res.status(200).json(data);
    } catch (err) {
        console.error('Erro ao buscar perfil:', err);
        res.status(500).json({ message: 'Erro no servidor' });
    }
});

// Endpoint para inserir ou atualizar informações do perfil
router.post('/update-profile', async (req, res) => {
    const { userId, name, email, cpf, telefone } = req.body;

    // Verifica se todos os campos necessários estão presentes
    if (!userId || !name || !email || !cpf || !telefone) {
        return res.status(400).json({ error: 'Todos os campos são necessários.' });
    }

    try {
        // Atualiza ou insere os dados na tabela profile_infos para o userId especificado
        const { data, error } = await supabase
            .from('users_info')
            .upsert([{ id: userId, name, email, cpf, telefone }]);

        if (error) {
            throw error;
        }

        res.status(200).json({ message: 'Perfil atualizado com sucesso!', data });
    } catch (err) {
        console.error('Erro ao atualizar perfil:', err);
        res.status(500).json({ message: 'Erro no servidor' });
    }
});

// Endpoint para pegar registros de pontos de um usuário
router.get('/points/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        // Busca os registros de pontos na tabela points_records com base no userId
        const { data, error } = await supabase
            .from('points_records')
            .select('*')
            .eq('id_user', userId);

        if (error) {
            throw error;
        }

        if (data.length === 0) {
            return res.status(404).json({ message: 'Nenhum registro de pontos encontrado para este usuário.' });
        }

        res.status(200).json(data);
    } catch (err) {
        console.error('Erro ao buscar registros de pontos:', err);
        res.status(500).json({ message: 'Erro no servidor' });
    }
});

router.get('/points/:recordId', async (req, res) => {
    const { recordId } = req.query;

    try {
        if (!recordId) {
            return res.status(400).json({ message: 'Parâmetros recordId são necessários.' });
        }

        // Busca o registro específico de pontos na tabela points_records com base no recordId e point
        const { data, error } = await supabase
            .from('points_records')
            .select('*')
            .eq('id', recordId) // Considera-se que a coluna para o ID do registro é 'id'

        if (error) {
            throw error;
        }

        if (!data) {
            return res.status(404).json({ message: 'Registro de pontos não encontrado.' });
        }

        res.status(200).json(data);
    } catch (err) {
        console.error('Erro ao buscar registro de pontos:', err);
        res.status(500).json({ message: 'Erro no servidor' });
    }
});



module.exports = router;