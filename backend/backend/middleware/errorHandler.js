// middleware/errorHandler.js
module.exports = (err, req, res, next) => {
    const errorData = {
        type: 'EXPRESS_ERROR',
        message: err.message,
        stack: err.stack,
        route: req.originalUrl,
        method: req.method,
        time: new Date().toISOString()
    }

    // envia para o socket
    req.app.get('io').emit('admin-alert', errorData)

    console.error(errorData)

    res.status(500).json({ error: 'Internal Server Error' })
}
