const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());
const swaggerUi = require('swagger-ui-express'); 
const swaggerDocument = require('./swagger.json');

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument)); 

app.use(express.json());


let users = []; // Масив для зберігання користувачів
let devices = []; // Масив для зберігання пристроїв
let deviceImages = {}; // Об'єкт для зберігання зображень пристроїв
let devicesInUse = {}; // Об'єкт для зберігання пристроїв, які використовують користувачі
const JWT_SECRET = 'your-secret-key'; // Змініть на ваш секретний ключ

// Реєстрація користувача
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const userExists = users.some(user => user.username === username);
  if (userExists) {
    return res.status(409).send({ message: 'Username already exists' });
  }
  const hashedPassword = await bcrypt.hash(password, 8);
  const newUser = { username, password: hashedPassword };
  users.push(newUser);
  res.status(201).send({ message: 'User registered' });
});

// Вхід користувача та генерація токена
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).send({ message: 'Invalid credentials' });
  }
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
  res.send({ token });
});

// Middleware для аутентифікації
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// CRUD операції для пристроїв
app.get('/devices', authenticateToken, (req, res) => {
  res.json(devices);
});

app.post('/devices', authenticateToken, (req, res) => {
  const { name, description, serialNumber, manufacturer } = req.body;
  const newDevice = { name, description, serialNumber, manufacturer };
  devices.push(newDevice);
  res.status(201).send({ message: 'Device added', device: newDevice });
});

app.put('/devices/:serialNumber', authenticateToken, (req, res) => {
  const { serialNumber } = req.params;
  const deviceIndex = devices.findIndex(device => device.serialNumber === serialNumber);
  if (deviceIndex === -1) {
    return res.status(404).send({ message: 'Device not found' });
  }
  const updatedDevice = { ...devices[deviceIndex], ...req.body };
  devices[deviceIndex] = updatedDevice;
  res.send({ message: 'Device updated', device: updatedDevice });
});

app.delete('/devices/:serialNumber', authenticateToken, (req, res) => {
  const { serialNumber } = req.params;
  devices = devices.filter(device => device.serialNumber !== serialNumber);
  res.send({ message: 'Device removed' });
});

// Завантаження зображення для пристрою
app.post('/devices/:serialNumber/image', authenticateToken, (req, res) => {
  const { serialNumber } = req.params;
  const { imageUrl } = req.body;
  deviceImages[serialNumber] = imageUrl;
  res.send({ message: 'Image uploaded for device', imageUrl });
});

// Взяття пристрою у користування
app.post('/checkout-device/:serialNumber', authenticateToken, (req, res) => {
  const { username } = req.user;
  const { serialNumber } = req.params;
  if (!devices.some(device => device.serialNumber === serialNumber)) {
    return res.status(404).send({ message: 'Device not found' });
  }
  if (devicesInUse[username] && devicesInUse[username].includes(serialNumber)) {
    return res.status(400).send({ message: 'User already checked out this device' });
  }
  devicesInUse[username] = (devicesInUse[username] || []).concat(serialNumber);
  res.send({ message: 'Device checked out', serialNumber });
});

// Повернення пристрою
app.post('/return-device/:serialNumber', authenticateToken, (req, res) => {
  const { username } = req.user;
  const { serialNumber } = req.params;
  if (!devicesInUse[username] || !devicesInUse[username].includes(serialNumber)) {
    return res.status(400).send({ message: 'Device not checked out by user' });
  }
  devicesInUse[username] = devicesInUse[username].filter(sNum => sNum !== serialNumber);
  res.send({ message: 'Device returned', serialNumber });
});

// Перегляд пристроїв, взятих у користування
app.get('/my-devices', authenticateToken, (req, res) => {
  const { username } = req.user;
  const userDevices = devicesInUse[username] || [];
  res.json({ devices: userDevices.map(serialNumber => ({
    serialNumber,
    imageUrl: deviceImages[serialNumber]
  })) });
});

// Запуск сервера
app.listen(3000, () => {
  console.log('Server started on port 3000');
});
