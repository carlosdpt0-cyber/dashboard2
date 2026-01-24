// errors/globalErrors.js
module.exports = (io) => {

    process.on('uncaughtException', (err) => {
        io.emit('admin-alert', {
            type: 'UNCAUGHT_EXCEPTION',
            message: err.message,
            stack: err.stack,
            time: new Date().toISOString()
        })
    })

    process.on('unhandledRejection', (reason) => {
        io.emit('admin-alert', {
            type: 'UNHANDLED_REJECTION',
            message: reason?.message || reason,
            stack: reason?.stack || null,
            time: new Date().toISOString()
        })
    })

}
