/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import jwt from 'jsonwebtoken'
import fs from 'fs'
import path from 'path'

// --- BẮT ĐẦU ĐOẠN CODE CUSTOM CHO DỰ ÁN AI ---

// 1. Tạo morgan token lấy User_ID
morgan.token('userId', function (req: any) {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const decoded: any = jwt.decode(token); // Giải mã token không cần verify chữ ký
      if (decoded && decoded.data) {
        return String(decoded.data.id); // Juice Shop lưu ID ở decoded.data.id
      }
    }
  } catch (e) {}
  return 'Guest'; // Nếu không đăng nhập
});

// 2. Tạo morgan token lấy Role
morgan.token('userRole', function (req: any) {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const decoded: any = jwt.decode(token);
      if (decoded && decoded.data) {
        // Juice Shop có thể dùng field role, hoặc ta dựa vào email để xác định
        if (decoded.data.role) return decoded.data.role;
        if (decoded.data.email && decoded.data.email.includes('admin')) return 'Admin';
        return 'Customer';
      }
    }
  } catch (e) {}
  return 'Guest';
});

// 3. (Tùy chọn) Ghi lại Body (chỉ lấy key) để bắt IDOR trong POST/PUT
morgan.token('reqBodyKeys', function (req: any) {
    if (req.body && Object.keys(req.body).length > 0) {
        return JSON.stringify(Object.keys(req.body));
    }
    return 'none';
});

// --- KẾT THÚC ĐOẠN CODE CUSTOM ---
// Tạo luồng ghi vào file ai_access.log
const aiLogStream = fs.createWriteStream(path.join(__dirname, 'ai_access.log'), { flags: 'a' });

// Định dạng log thành JSON chuẩn để nạp vào AI
const aiLogFormat = JSON.stringify({
  timestamp: ':date[iso]',
  ip: ':remote-addr',
  method: ':method',
  url: ':url',
  status: ':status',
  userId: ':userId',
  role: ':userRole',
  bodyKeys: ':reqBodyKeys',
  responseTimeMs: ':response-time'
});

// Kích hoạt middleware ghi log
app.use(morgan(aiLogFormat, { stream: aiLogStream }));

async function app () {
  const { default: validateDependencies } = await import('./lib/startup/validateDependenciesBasic')
  await validateDependencies()

  const server = await import('./server')
  await server.start()
}

app()
  .catch(err => {
    throw err
  })
