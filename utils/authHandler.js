let jwt = require('jsonwebtoken')
let userController = require("../controllers/users")
const fs = require('fs');
const path = require('path');

const publicKey = fs.readFileSync(path.join(__dirname, '../public.key'), 'utf8');

module.exports = {
    checkLogin: async function (req, res, next) {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).send({ message: "Yêu cầu đăng nhập. Token không được cung cấp." });
            }
            const token = authHeader.split(" ")[1];

            // jwt.verify tự động xử lý lỗi token hết hạn
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
            let user = await userController.FindUserById(result.id);
            if (user) {
                req.user = user;
                next();
            } else {
                res.status(401).send({ message: "Không tìm thấy người dùng tương ứng với token." });
            }
        } catch (error) {
            res.status(401).send({ message: "Token không hợp lệ hoặc đã hết hạn." });
        }
    }
}