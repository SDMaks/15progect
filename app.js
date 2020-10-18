require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { errors, celebrate, Joi } = require('celebrate');
const routCard = require('./routes/routCard.js');

const routUser = require('./routes/routUser.js');
const { createUser, login } = require('./controllers/users.js');

const auth = require('./middlewares/auth');

const app = express();

mongoose.connect('mongodb://localhost:27017/mestodb', {
  useNewUrlParser: true,
  useCreateIndex: true,
  useFindAndModify: false,
  useUnifiedTopology: true,
});

const { PORT = 3220 } = process.env;

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 мин
  max: 100, // ограничение кс каждого IP до 100 запросов
});

app.use(limiter);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(helmet());
app.post('/signin', celebrate({
  body: Joi.object().keys({
    email: Joi.string().required().pattern(/(([a-zA-Z])|(\d))+((([a-zA-Z]?)|(\d?))*)(([-](([a-zA-Z])|(\d)))?[a-zA-Z]*\d*)*(([_](([a-zA-Z])|(\d)))?[a-zA-Z]*\d*)*((([.](([a-zA-Z])|(\d)))?[a-zA-Z]*\d*)|(([-](([a-zA-Z])|(\d)))?[a-zA-Z]*\d*)|(([_](([a-zA-Z])|(\d)))?[a-zA-Z]*\d*))*[@](((\w+\d*(([-]\w+\d*)|([-]\d+\w*)))|(\d+))|((\w+\d*[.]?\w+\d*)|(\w+\d*)))[.][a-z][a-z][a-z]?/),
    password: Joi.string().required().min(8),
  }),
}), login);
app.post('/signup', celebrate({
  body: Joi.object().keys({
    name: Joi.string().required().min(2).max(30),
    about: Joi.string().required().min(2).max(30),
    avatar: Joi.string().required().pattern(/http(s)?[:][/]{2}(www[.])?(((((\d*[a-z]+\d*((([-]\d*[a-z]+\d*))*)?((([-][a-z]*\d+[a-z]*))*)?)|([a-z]*\d+[a-z]*\d*))([-]\d+[a-z]*\d*)?([-][a-z]+\d*[a-z]*)?(([-]\d+[a-z]*\d*)*([-][a-z]+\d*[a-z]*)*)[.][a-z][a-z]([a-z])?((([:](([1-9])|([1-9][0-9])|([1-9][0-9][0-9])|([1-9][0-9][0-9][0-9])|(6553[0-5])|(655[0-3][0-5])|(655[0-2][0-9])|(65[0-5][0-3][0-5])|(65[0-4][0-9][0-9])|(6[0-5][0-5][0-3][0-5])|(6[0-4][0-9][0-9][0-9])|([1-6][0-5][0-5][0-3][0-5])|([1-5][0-9][0-9][0-9][0-9])))|((([/]((\d*(([a-z]+)|(\d+))\d*[a-z]*)|([a-z]*(([a-z]+)|(\d+))[a-z]*\d*))[/])*)))|((([/]\d*(([a-z]+)|(\d+))\d*[a-z]*([-]?\d*(([a-z]+)|(\d+))\d*[a-z]*)?([/]|[#]))|((([/]\d*(([a-z]+)|(\d+))\d*[a-z]*([-]?\d*(([a-z]+)|(\d+))\d*[a-z]*)?[/])((\d*(([a-z]+)|(\d+))\d*[a-z]*([-]?\d*(([a-z]+)|(\d+))\d*[a-z]*)?[/])*)*)(\d*(([a-z]+)|(\d+))\d*[a-z]*([-]?\d*(([a-z]+)|(\d+))\d*[a-z]*)?([/]|[#]))))))?)|(\d*(([a-z]+)|(\d+))(([.]?[a-z]+)?(([-]?[a-z]+\d*[a-z]*)*([-]\d+[a-z]*\d*)*)?\d*[a-z]*)?[.][a-z][a-z]([a-z])?)(([:](([1-9])|([1-9][0-9])|([1-9][0-9][0-9])|([1-9][0-9][0-9][0-9])|(6553[0-5])|(655[0-3][0-5])|(655[0-2][0-9])|(65[0-5][0-3][0-5])|(65[0-4][0-9][0-9])|(6[0-5][0-5][0-3][0-5])|(6[0-4][0-9][0-9][0-9])|([1-6][0-5][0-5][0-3][0-5])|([1-5][0-9][0-9][0-9][0-9]))[/]?)|((([/]((\d*[a-z]+\d*[a-z]*)|([a-z]*\d+[a-z]*\d*))[/])*))))|(\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}[:]((([1-9])|([1-9][0-9]))|([1-9][0-9][0-9])|([1-9][0-9][0-9][0-9])|(6553[0-5])|(655[0-3][0-5])|(655[0-2][0-9])|(65[0-5][0-3][0-5])|(65[0-4][0-9][0-9])|(6[0-5][0-5][0-3][0-5])|(6[0-4][0-9][0-9][0-9])|([1-6][0-5][0-5][0-3][0-5])|([1-5][0-9][0-9][0-9][0-9]))((([/]\d*[a-z]+\d*[a-z]*([-]?\d*[a-z]+\d*[a-z]*)?[#])|([/][a-z]*\d+[a-z]*([-][a-z]*\d+[a-z]*\d*)*[/]([a-z]*\d+([a-z]*\d*([-][a-z]*\d+[a-z]*\d*)+)?([/][a-z]*\d+[a-z]*\d*([-][a-z]*\d+[a-z]*\d*)*)*)?[#])|([a-z]*\d+[a-z]*\d*([-][a-z]*\d+[a-z]*\d*)*[#])|([/]((\d+)|([a-z]+))+([-][a-z]*(((\d+)|([a-z]+))[a-z]*\d*))*([/]((\d+)|([a-z]+))+([-][a-z]*(((\d+)|([a-z]+))[a-z]*\d*))*)*[#])|((([/]\d*[a-z]+\d*[a-z]*([-]?\d*[a-z]+\d*[a-z]*)?[/])((\d*[a-z]+\d*[a-z]*([-]?\d*[a-z]+\d*[a-z]*)?[/])*)*)(\d*[a-z]+\d*[a-z]*([-]?\d*[a-z]+\d*[a-z]*)?[#])))?)))/),
    email: Joi.string().required().pattern(/(([a-zA-Z])|(\d))+((([a-zA-Z]?)|(\d?))*)(([-](([a-zA-Z])|(\d)))?[a-zA-Z]*\d*)*(([_](([a-zA-Z])|(\d)))?[a-zA-Z]*\d*)*((([.](([a-zA-Z])|(\d)))?[a-zA-Z]*\d*)|(([-](([a-zA-Z])|(\d)))?[a-zA-Z]*\d*)|(([_](([a-zA-Z])|(\d)))?[a-zA-Z]*\d*))*[@](((\w+\d*(([-]\w+\d*)|([-]\d+\w*)))|(\d+))|((\w+\d*[.]?\w+\d*)|(\w+\d*)))[.][a-z][a-z][a-z]?/),
    password: Joi.string().required().min(8),
  }),
}), createUser);
app.use(auth);
app.use('/cards', routCard);
app.use('/users', routUser);

app.use((req, res) => {
  res.status(404).send({ message: 'Запрашиваемый ресурс не найден' });
});

app.use(errors());
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  // если у ошибки нет статуса, выставляем 500
  const { statusCode = 500, message } = err;
  if (err.name === 'ValidationError') {
    return res.status(400).send({ message: 'Невалидный запрос' });
  }
  return res
    .status(statusCode)
    .send({
      // проверяем статус и выставляем сообщение в зависимости от него
      message: statusCode === 500
        ? 'На сервере произошла ошибка'
        : message,
    });
});

app.listen(PORT);
