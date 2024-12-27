import express, { Request, Response, NextFunction, RequestHandler } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const app = express();
app.use(express.json());

// 타입 정의
interface JwtPayload {
    iss: string;
    sub: string;
    exp?: number;
    iat?: number;
}

interface AuthRequest extends Request {
    user?: JwtPayload;
}

// JWT 비밀키 생성
const secretKey: string = crypto.randomBytes(64).toString('hex');

// Access Token 생성
function makeAccessToken(username: string): string {
    return jwt.sign(
        {
            iss: 'your-app',
            sub: username
        },
        secretKey,
        {
            algorithm: 'HS512',
            expiresIn: '1h'
        }
    );
}

// Refresh Token 생성
function makeRefreshToken(username: string): string {
    return jwt.sign(
        {
            iss: 'your-app',
            sub: username
        },
        secretKey,
        {
            algorithm: 'HS512',
            expiresIn: '7d'
        }
    );
}

// JWT 토큰 검증 미들웨어
const verifyToken = ((req: AuthRequest, res: Response, next: NextFunction): Response | void => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    const token = authHeader.substring(7);
    try {
        const payload = jwt.verify(token, secretKey, { algorithms: ['HS512'] }) as JwtPayload;
        req.user = payload;
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid token' });
    }
}) as RequestHandler<{}, any, any, any, AuthRequest>;

// 로그인 라우트
app.post('/login', ((req, res) => {
    const { username } = req.body;
    if (!username) {
        return res.status(400).json({ message: 'Username is required' });
    }

    const accessToken = makeAccessToken(username);
    const refreshToken = makeRefreshToken(username);

    res.json({ accessToken, refreshToken });
}) as RequestHandler);

// 보호된 리소스 라우트
app.get('/resource', verifyToken, ((req: AuthRequest, res: Response) => {
    res.json({ message: `Hello, ${req.user?.sub}!` });
}) as RequestHandler<{}, any, any, any, AuthRequest>);

// 토큰 갱신 라우트
app.post('/refresh', ((req: Request, res: Response) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(400).json({ message: 'Refresh token is required' });
    }

    try {
        const payload = jwt.verify(refreshToken, secretKey, { algorithms: ['HS512'] }) as JwtPayload;
        const accessToken = makeAccessToken(payload.sub);
        res.json({ accessToken });
    } catch (error) {
        res.status(401).json({ message: 'Invalid refresh token' });
    }
}) as RequestHandler);

// 404 처리
app.use((req: Request, res: Response) => {
    res.status(404).json({ message: '404' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});