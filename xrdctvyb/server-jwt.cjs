const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require('path');
const { Sequelize, DataTypes } = require('sequelize');
const session = require('express-session');
const bodyParser = require('body-parser');

const app = express();
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: './database.sqlite',
  logging: console.log
});

const JWT_SECRET = "my_super_jwt_secret_12345";

app.use(express.json()); 
app.use(express.urlencoded({ extended: true })); 
app.use(express.static('public'));

// Модели
const Role = sequelize.define('Role', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  name: { type: DataTypes.STRING, allowNull: false, unique: true },
});

const User = sequelize.define('User', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  login: { type: DataTypes.STRING, allowNull: false, unique: true },
  password: { type: DataTypes.STRING, allowNull: false },
  roleId: { type: DataTypes.INTEGER, allowNull: false, references: { model: Role, key: 'id' } },
});

const Employee = sequelize.define('Employee', {
  firstName: { type: DataTypes.STRING, allowNull: false, validate: { notEmpty: true } },
  lastName: { type: DataTypes.STRING, allowNull: false, validate: { notEmpty: true } },
  position: { type: DataTypes.ENUM('developer', 'designer', 'manager', 'analyst', 'hr'), defaultValue: 'developer' },
  salary: { type: DataTypes.DECIMAL(10, 2), validate: { min: 0 } },
  hireDate: { type: DataTypes.DATEONLY, defaultValue: DataTypes.NOW }
}, { tableName: 'employees', timestamps: true });

const Product = sequelize.define('Product', {
  name: { type: DataTypes.STRING(200), validate: { len: [2, 200] } },
  description: DataTypes.TEXT,
  price: { type: DataTypes.DECIMAL(10, 2), validate: { min: 0 } },
  category: { type: DataTypes.ENUM('electronics', 'clothing', 'books', 'food', 'sports') },
  inStock: { type: DataTypes.BOOLEAN, defaultValue: true },
  stockQuantity: { type: DataTypes.INTEGER, defaultValue: 0, validate: { min: 0 } }
}, { tableName: 'products', timestamps: true, paranoid: true });

const Task = sequelize.define('Task', {
  title: { type: DataTypes.STRING(100), validate: { notEmpty: true } },
  description: DataTypes.TEXT,
  priority: { type: DataTypes.ENUM('low', 'medium', 'high', 'critical'), defaultValue: 'medium' },
  status: { type: DataTypes.ENUM('pending', 'in_progress', 'completed', 'cancelled'), defaultValue: 'pending' },
  dueDate: { type: DataTypes.DATE, validate: { isDate: true } },
  estimatedHours: { type: DataTypes.FLOAT, validate: { min: 0 } }
}, { tableName: 'tasks', timestamps: true });

const Order = sequelize.define('Order', {
  orderNumber: { type: DataTypes.STRING(20), unique: true },
  totalAmount: { type: DataTypes.DECIMAL(12, 2), validate: { min: 0 } },
  paymentStatus: { type: DataTypes.ENUM('pending', 'paid', 'failed', 'refunded'), defaultValue: 'pending' },
  shippingStatus: { type: DataTypes.ENUM('processing', 'shipped', 'delivered', 'cancelled'), defaultValue: 'processing' },
  shippingAddress: { type: DataTypes.JSON, allowNull: false },
  customerNotes: DataTypes.TEXT,
}, { 
  tableName: 'orders', 
  timestamps: true,
  hooks: { 
    beforeCreate: order => { 
      if (!order.orderNumber) order.orderNumber = `ORD-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }
  }
});

// Ассоциации устанавливаются до sync
const setupAssociations = () => {
  Role.hasMany(User, { foreignKey: 'roleId' });
  User.belongsTo(Role, { foreignKey: 'roleId' });

  User.hasMany(Task, { foreignKey: 'userId', as: 'tasks', onDelete: 'SET NULL', onUpdate: 'CASCADE' });
  Task.belongsTo(User, { foreignKey: 'userId', as: 'assignee' });

  Employee.hasMany(Task, { foreignKey: 'employeeId', as: 'assignedTasks', onDelete: 'SET NULL', onUpdate: 'CASCADE' });
  Task.belongsTo(Employee, { foreignKey: 'employeeId', as: 'assignedEmployee' });

  User.hasMany(Order, { foreignKey: 'userId', as: 'orders', onDelete: 'SET NULL', onUpdate: 'CASCADE' });
  Order.belongsTo(User, { foreignKey: 'userId', as: 'customer' });

  Employee.hasMany(Order, { foreignKey: 'managerId', as: 'managedOrders', onDelete: 'SET NULL', onUpdate: 'CASCADE' });
  Order.belongsTo(Employee, { foreignKey: 'managerId', as: 'orderManager' });

  Order.belongsToMany(Product, { through: 'OrderProducts', foreignKey: 'orderId', otherKey: 'productId', as: 'products' });
  Product.belongsToMany(Order, { through: 'OrderProducts', foreignKey: 'productId', otherKey: 'orderId', as: 'orders' });

  User.hasOne(Employee, { foreignKey: 'userId', as: 'employeeProfile', onDelete: 'CASCADE', onUpdate: 'CASCADE' });
  Employee.belongsTo(User, { foreignKey: 'userId', as: 'userAccount' });
};

// Создание таблиц и инициализация базы
(async () => {
  try {
    await sequelize.authenticate();
    console.log('Подключение к SQLite успешно установлено');

    setupAssociations(); // обязательно вызвать до sync
    await sequelize.sync({ force: true }); // force: true для пересоздания таблиц

    // Создаём роль и пользователя с хешированным паролем для теста
    const roleUser = await Role.create({ name: 'user' });
    const hashedPassword = await bcrypt.hash('qwe', 10);
    const user = await User.create({ login: 'ofmayff@gmail.com', password: hashedPassword, roleId: roleUser.id });
    console.log('Пользователь создан:', user.login);

    console.log('База данных инициализирована');
  } catch (e) {
    console.error('Ошибка БД:', e);
  }
})();

// Middleware и сессии
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: false,
}));

function isAuthenticated(req, res, next) {
  if (req.session.user) next();
  else res.redirect('/login');
}

function hasRole(roleName) {
  return async (req, res, next) => {
    if (req.session.user) {
      const user = await User.findByPk(req.session.user.id, { include: Role });
      if (user && user.Role && user.Role.name === roleName) next();
      else res.status(403).send('Доступ запрещен');
    } else {
      res.redirect('/login');
    }
  };
}

// JWT аутентификация
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => err ? res.sendStatus(403) : (req.user = user) && next());
};

// Роуты
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ login: username, password: hashedPassword, roleId: 1 });
    res.status(201).send("User registered");
  } catch (error) {
    console.log('Ошибка регистрации:', error);
    res.status(500).send("Registration error");
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ where: { login: username } });
    if (!user) return res.status(400).send("Cannot find user");
    if (await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });
      res.json({ token });
    } else {
      res.status(401).send("Not Allowed");
    }
  } catch (error) {
    console.log('Ошибка входа:', error);
    res.status(500).send("Login error");
  }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get("/dashboard", authenticateToken, (req, res) => res.send(`Welcome to your JWT dashboard, ${req.user.username}!`));

// Запуск сервера
app.listen(3001, () => console.log("Server running on port 3001"));
