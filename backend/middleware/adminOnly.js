const User = require('../models/User');

module.exports = async function(req, res, next) {
    // req.user is set by authenticateToken
    const user = await User.findById(req.user.id);
    if (!user || !user.isAdmin) {
        return res.status(403).json({ msg: 'Admins only' });
    }
    next();
};