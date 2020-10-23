/* eslint-disable consistent-return */
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const userSchema = require('../models/user');

const { NODE_ENV, JWT_SECRET } = process.env;

const InBaseNotFound = require('../errors/InBaseNotFound'); // 404
const BadRequest = require('../errors/badRequest'); // 400
const ErrorUniqueUser = require('../errors/errorUniqueUser'); // 409

module.exports.findUser = (req, res, next) => {
  userSchema.find({})
    .then((user) => {
      if (!user.length) {
        throw new InBaseNotFound('Нет пользователей в базе');
      }
      res.send({ data: user });
    })
    .catch(next);
};

module.exports.findUserId = (req, res, next) => {
  try {
    const { userId } = req.params;
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new BadRequest('Не валидный запрос');
    }

    userSchema.findById(userId)
      .orFail(() => {
        throw new InBaseNotFound('Нет пользователя в базе');
      })
      .then((user) => res.send({ data: user }))
      .catch(next);
  } catch (err) {
    next(err);
  }
};

module.exports.createUser = (req, res, next) => {
  const {
    name, about, avatar, email,
  } = req.body;

  bcrypt.hash(req.body.password, 10)
    .then((hash) => userSchema.create({
      name,
      about,
      avatar,
      email,
      password: hash,

    }))
    .then((user) => res.status(201).send({ _id: user._id, email: user.email }))
    .catch((err) => {
      if (err.name === 'MongoError' && err.code === 11000) {
        throw new ErrorUniqueUser('Пользователь с таким Email уже зарегестрирован!');
      }
    })
    .catch(next);
};

module.exports.login = (req, res, next) => {
  const { email, password } = req.body;
  return userSchema.findUserByCredentials(email, password)
    .then((user) => {
      // аутентификация успешна! пользователь в переменной user
      const token = jwt.sign({ _id: user._id }, NODE_ENV === 'production' ? JWT_SECRET : 'dev-secret', { expiresIn: '7d' });
      res
        .cookie('jwt', token, {
          maxAge: 3600000 * 24 * 7,
          httpOnly: true,
          sameSite: true,
        })
        .send({ message: 'Вы авторизованы' });
    })
    .catch((err) => {
      next(err);
    });
};

module.exports.updateUser = (req, res, next) => {
  const { name, about } = req.body;
  const owner = req.user._id;
  userSchema.findByIdAndUpdate(owner, { name, about }, { new: true, runValidators: true })
    .then((user) => {
      if (!user) {
        throw new InBaseNotFound('Нет пользователя в базе');
      }
      res.send({ data: user });
    })
    .catch(next);
};

module.exports.updateAvatar = (req, res, next) => {
  const { avatar } = req.body;
  const owner = req.user._id;

  userSchema.findByIdAndUpdate(owner, { avatar }, { new: true, runValidators: true })
    .then((user) => {
      if (!user) {
        throw new InBaseNotFound('Нет пользователя в базе');
      }
      res.send({ data: user });
    })
    .catch(next);
};
