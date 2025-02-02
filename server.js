require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const winston = require('winston');
const { createLogger, format, transports } = winston;
require('winston-daily-rotate-file');
const compression = require('compression');

// 로깅 설정
const logTransport = new transports.DailyRotateFile({
    filename: 'app-%DATE%.log',
    dirname: 'logs',
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '14d'
});

const logger = createLogger({
    level: 'info',
    format: format.combine(
        format.timestamp(),
        format.json()
    ),
    transports: [
        logTransport,
        new transports.Console({ format: format.simple() })
    ]
});

const app = express();
app.use(cors({
    origin: process.env.SERVER_ORIGIN || "http://localhost:5000",
    methods: ["GET", "POST"],
    credentials: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(compression());

// 세션 설정
app.use(session({
    secret: process.env.SESSION_SECRET || 'your_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // HTTPS 사용 시 true로 변경
        httpOnly: true,
        maxAge: 60 * 60 * 1000
    }
}));

const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: process.env.SERVER_ORIGIN || "http://localhost:5000",
        methods: ["GET", "POST"],
        credentials: true
    },
    pingTimeout: 60000,
    pingInterval: 25000,
    maxHttpBufferSize: 1e6
});

// Map으로 사용자 데이터 저장
const usersData = new Map();

// 사용자 데이터 정리 함수
function cleanupInactiveUsers() {
    const inactiveThreshold = Date.now() - (30 * 60 * 1000); // 30분
    let cleanedCount = 0;

    for (const [username, userData] of usersData.entries()) {
        if (!userData.timestamp || new Date(userData.timestamp).getTime() < inactiveThreshold) {
            usersData.delete(username);
            cleanedCount++;
            logger.info(`Inactive user removed: ${username}`);
        }
    }

    if (cleanedCount > 0) {
        logger.info(`Cleaned up ${cleanedCount} inactive users`);
    }
}

// 5분마다 inactive user 정리
setInterval(cleanupInactiveUsers, 5 * 60 * 1000);

// 관리자 비밀번호 해싱
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "xorhkd12!@";
const hashedPassword = bcrypt.hashSync(ADMIN_PASSWORD, 10);

// 인증 미들웨어
function isAuthenticated(req, res, next) {
    if (req.session.isAuthenticated) {
        next();
    } else {
        res.redirect('/login');
    }
}

// 라우트 설정
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
    const { password } = req.body;
    logger.info('로그인 시도');

    if (bcrypt.compareSync(password, hashedPassword)) {
        req.session.isAuthenticated = true;
        logger.info('로그인 성공');
        res.redirect('/dashboard');
    } else {
        logger.warn('로그인 실패: 잘못된 비밀번호');
        res.send(`
            <script>
                alert('비밀번호가 일치하지 않습니다.');
                window.location.href = '/login';
            </script>
        `);
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            logger.error('로그아웃 중 오류:', err);
            return res.redirect('/dashboard');
        }
        logger.info('로그아웃 성공');
        res.redirect('/');
    });
});

app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Socket.IO 연결 처리
io.on('connection', (socket) => {
    logger.info(`새로운 클라이언트 연결: ${socket.id}`);

    // 하트비트 설정
    const heartbeat = setInterval(() => {
        if (socket.connected) {
            socket.emit('heartbeat');
        }
    }, 20000);

    // 이벤트 리스너 등록
    socket.on('heartbeat-response', async () => {
        // 클라이언트 생존신호 처리
    });

    socket.on('request_initial_data', async () => {
        try {
            const allUserData = Array.from(usersData.values()).map(user => ({
                name: user.name,
                user_ip: user.user_ip,
                total_balance: user.total_balance || 0,
                current_profit_rate: user.current_profit_rate || 0,
                unrealized_pnl: user.unrealized_pnl || 0,
                current_total_asset: user.current_total_asset || 0,
                server_status: user.server_status || 'Disconnected',
                timestamp: user.timestamp || new Date().toISOString(),
                cumulative_profit: user.cumulative_profit || 0,
                target_profit: user.target_profit || 500,
                isApproved: user.isApproved || false,
                display_profit: user.display_profit || 0
            }));
            socket.emit('initial_data', allUserData);
        } catch (error) {
            logger.error('초기 데이터 전송 오류:', error);
            socket.emit('error', { message: '초기 데이터 전송 중 오류가 발생했습니다.' });
        }
    });

    socket.on('user_info_update', async (data) => {
        try {
            if (!data.name || !data.user_ip || !data.server_status) {
                socket.emit('error', { message: '잘못된 사용자 정보 데이터입니다.' });
                return;
            }

            const userData = usersData.get(data.name) || {};
            const updatedData = {
                ...userData,
                name: data.name,
                user_ip: data.user_ip,
                server_status: data.server_status,
                socketId: socket.id,
                timestamp: data.timestamp || new Date().toISOString(),
                isApproved: data.isApproved !== undefined ? data.isApproved : (userData.isApproved || false),
                target_profit: data.target_profit !== undefined ? data.target_profit : (userData.target_profit || 500),
                display_profit: data.display_profit != null ? data.display_profit : (userData.display_profit || 0),
                cumulative_profit: data.cumulative_profit !== undefined ? data.cumulative_profit : (userData.cumulative_profit || 0)
            };

            usersData.set(data.name, updatedData);
            io.emit('update_user_info', updatedData);
            
        } catch (error) {
            logger.error('사용자 정보 업데이트 오류:', error);
            socket.emit('error', { message: '사용자 정보 업데이트 중 오류가 발생했습니다.' });
        }
    });

    socket.on('trade_executed', async (data) => {
        try {
            logger.info(`거래 실행 데이터: ${JSON.stringify(data)}`);
        } catch (error) {
            logger.error('거래 실행 처리 오류:', error);
            socket.emit('error', { message: '거래 처리 중 오류가 발생했습니다.' });
        }
    });

    socket.on('update_data', async (data) => {
        try {
            if (!data.name) {
                socket.emit('error', { message: '사용자 이름이 누락되었습니다.' });
                return;
            }

            const userData = usersData.get(data.name) || {};
            const updatedData = {
                ...userData,
                name: data.name,
                user_ip: data.user_ip || userData.user_ip,
                total_balance: data.total_balance || 0,
                current_profit_rate: data.current_profit_rate || 0,
                unrealized_pnl: data.unrealized_pnl || 0,
                current_total_asset: data.current_total_asset || 0,
                server_status: data.server_status || 'Connected',
                timestamp: data.timestamp || new Date().toISOString(),
                cumulative_profit: data.cumulative_profit || 0,
                display_profit: data.display_profit != null ? data.display_profit : (userData.display_profit || 0),
                target_profit: data.target_profit || userData.target_profit || 500,
                isApproved: data.isApproved || userData.isApproved || false,
                socketId: socket.id
            };

            usersData.set(data.name, updatedData);
            logger.info(`사용자 ${data.name}의 상태 업데이트: ${JSON.stringify(updatedData)}`);
            io.emit('update_data', updatedData);

            // 목표 달성 이벤트 처리 (필요한 경우)
            if (updatedData.display_profit >= updatedData.target_profit && updatedData.isApproved) {
                io.emit('goal_achieved', { name: updatedData.name });
            }

        } catch (error) {
            logger.error('데이터 업데이트 오류:', error);
            socket.emit('error', { message: '데이터 업데이트 중 오류가 발생했습니다.' });
        }
    });

    socket.on('send_command', async (data) => {
        try {
            const { command, name } = data;
            if (!command || !name) {
                socket.emit('error', { message: '명령 또는 사용자 이름이 누락되었습니다.' });
                return;
            }

            const userData = usersData.get(name);
            if (!userData || !userData.socketId) {
                socket.emit('error', { message: '해당 사용자를 찾을 수 없습니다.' });
                return;
            }

            if (command === 'approve') {
                io.to(userData.socketId).emit('approve', { name });
                io.emit('update_approval_status', { name, isApproved: true });
                userData.isApproved = true;
                usersData.set(name, userData);
            } else if (command === 'cancel_approve') {
                io.to(userData.socketId).emit('cancel_approve', { name });
                io.emit('update_approval_status', { name, isApproved: false });
                userData.isApproved = false;
                usersData.set(name, userData);
            }
        } catch (error) {
            logger.error('명령 처리 오류:', error);
            socket.emit('error', { message: '명령 처리 중 오류가 발생했습니다.' });
        }
    });

    socket.on('set_target_profit', async (data) => {
        try {
            const { name, targetProfit } = data;
            const userData = usersData.get(name);
            
            if (!userData || !userData.socketId) {
                socket.emit('error', { message: '해당 사용자를 찾을 수 없습니다.' });
                return;
            }

            io.to(userData.socketId).emit('set_target_profit', { targetProfit });
            const updatedData = { ...userData, target_profit: targetProfit };
            usersData.set(name, updatedData);
            io.emit('update_data', updatedData);
            
        } catch (error) {
            logger.error('목표 수익금 설정 오류:', error);
            socket.emit('error', { message: '목표 수익금 설정 중 오류가 발생했습니다.' });
        }
    });

    socket.on('disconnect', async () => {
        try {
            clearInterval(heartbeat);
            logger.info(`클라이언트 연결 해제: ${socket.id}`);
            
            for (const [name, userData] of usersData.entries()) {
                if (userData.socketId === socket.id) {
                    userData.server_status = 'Disconnected';
                    userData.timestamp = new Date().toISOString();
                    usersData.set(name, userData);
                    break;
                }
            }
        } catch (error) {
            logger.error('연결 해제 처리 오류:', error);
        }
    });
});

// 에러 핸들링 미들웨어
app.use((err, req, res, next) => {
    logger.error('예상치 못한 오류:', err);
    res.status(500).json({
        success: false,
        error: '서버 오류가 발생했습니다.'
    });
});

// 메모리 사용량 모니터링 및 관리
function checkMemoryUsage() {
    const used = process.memoryUsage();
    const heapUsedMB = Math.round(used.heapUsed / 1024 / 1024);
    const heapTotalMB = Math.round(used.heapTotal / 1024 / 1024);
    const usageRatio = used.heapUsed / used.heapTotal;

    logger.info('메모리 사용량:', {
        rss: `${Math.round(used.rss / 1024 / 1024)} MB`,
        heapTotal: `${heapTotalMB} MB`,
        heapUsed: `${heapUsedMB} MB`,
        external: `${Math.round(used.external / 1024 / 1024)} MB`
    });

    // 메모리 사용률이 80% 이상이면 정리 시도
    if (usageRatio > 0.8) {
        logger.warn('높은 메모리 사용량 감지, 정리 시작');
        cleanupInactiveUsers();
        if (global.gc) {
            global.gc();
            logger.info('가비지 컬렉션 실행됨');
        }
    }
}

// 5분마다 메모리 체크
setInterval(checkMemoryUsage, 5 * 60 * 1000);

// 활성 연결 모니터링
setInterval(() => {
    const activeCount = io.sockets.sockets.size;
    logger.info(`활성 연결 수: ${activeCount}`);
    logger.info(`등록된 사용자 수: ${usersData.size}`);
}, 5 * 60 * 1000);

// 정상 종료 처리
async function gracefulShutdown() {
    logger.info('서버 종료 시작...');
    
    io.emit('server_shutdown', { message: '서버가 곧 종료됩니다.' });

    // 서버 상태 저장
    const serverState = {
        usersData: Array.from(usersData.entries()),
        timestamp: new Date().toISOString()
    };
    try {
        await fs.promises.writeFile('server-state.json', JSON.stringify(serverState, null, 2));
        logger.info('서버 상태가 저장되었습니다.');
    } catch (error) {
        logger.error('서버 상태 저장 실패:', error);
    }

    server.close(() => {
        logger.info('서버가 안전하게 종료되었습니다.');
        process.exit(0);
    });

    // 10초 후 강제 종료
    setTimeout(() => {
        logger.error('서버 강제 종료');
        process.exit(1);
    }, 10000);
}

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// 비정상 종료 처리
process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    setTimeout(() => {
        process.exit(1);
    }, 1000);
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection:', reason);
});

// 서버 시작
const PORT = process.env.PORT || 5000;
server.listen(PORT, async () => {
    logger.info(`서버가 포트 ${PORT}에서 실행 중입니다.`);

    // 시작 시 서버 상태 복구 시도
    try {
        if (fs.existsSync('server-state.json')) {
            const data = await fs.promises.readFile('server-state.json', 'utf8');
            const savedState = JSON.parse(data);
            if (savedState.usersData) {
                usersData.clear();
                savedState.usersData.forEach(([key, value]) => {
                    usersData.set(key, {
                        ...value,
                        server_status: 'Disconnected',  // 재시작 시 모든 연결 상태 초기화
                        timestamp: new Date().toISOString()
                    });
                });
                logger.info('이전 서버 상태가 복구되었습니다.');
            }
        }
    } catch (error) {
        logger.error('서버 상태 복구 실패:', error);
    }
});
