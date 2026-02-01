import jwt from "jsonwebtoken";

const isAuthenticated = async (req, res, next) => {
    try {
        const token = req.cookies.token;

        // 1. Token missing
        if (!token) {
            return res.status(401).json({
                message: "User not authenticated (token missing)",
                success: false,
            });
        }

        // 2. Token verification
        const decoded = jwt.verify(token, process.env.SECRET_KEY); // no need for await here

        // 3. Extra check (optional)
        if (!decoded || !decoded.userId) {
            return res.status(401).json({
                message: "Invalid token",
                success: false,
            });
        }

        // 4. Attach user ID to request
        req.id = decoded.userId;
        next();
    } catch (error) {
        console.error("Auth Error:", error.message);
        return res.status(401).json({
            message: "Authentication failed",
            success: false,
        });
    }
};

export default isAuthenticated;
