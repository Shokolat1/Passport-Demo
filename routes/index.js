var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local');

const { MongoClient, ObjectId } = require("mongodb");
const client = new MongoClient("mongodb://localhost:27017");

// ESTRATEGIA LOCAL
passport.use(new LocalStrategy(
  async function (username, password, done) {
    await client.connect()
    const db = client.db('passportTest');
    const collection = db.collection('users');

    let respuesta = await collection.findOne({ email: username })

    if (!respuesta) {
      console.log('Usuario inexistente')
      client.close()
      return done(null, false)
    }

    if (password != respuesta.pass) {
      console.log(`Contraseñas distintas: ${password} vs ${respuesta.pass}`)
      client.close()
      return done(null, false)
    }

    client.close()
    return done(null, respuesta);
  })
);

// SERIALIZAR INFO
passport.serializeUser(function (user, done) {
  done(null, user);
});

// DESERIALIZAR/DESENCRIPTAR INFO DE SESIÓN
passport.deserializeUser(async function (user, done) {
  await client.connect()
  const db = client.db('passportTest');
  const collection = db.collection('users');

  const us = collection.findOne({ _id: new ObjectId(user._id) })

  if (us != null) {
    done(null, user);
  }
});

// CHECA SI EL USUARIO TIENE UNA SESIÓN EXISTENTE
const isAuth = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  } else {
    res.redirect("/");
  }
};

// RUTAS --------------------------------------------------------------------------------------
// Inicio de Sesión
router.get('/', function (req, res, next) {
  res.render('index', { title: 'Passport Test' });
});

// Inicio de Sesión
router.get('/signup', function (req, res, next) {
  res.render('signup');
});

// Sesión Iniciada
router.get('/inside', isAuth, function (req, res, next) {
  console.log(req.session)
  res.render('welcome', { title: 'Bienvenido Usuario!' })
});

// Cerrar Sesión
router.get('/logout', function (req, res, next) {
  req.logout(function (err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

// Mandar info para Iniciar Sesión
router.post('/login', passport.authenticate('local', { failureRedirect: '/' }),
  function (req, res, next) {
    res.redirect('/inside');
  });

// Registrar usuario nuevo 
router.post('/signup', async function (req, res, next) {
  await client.connect()
  const db = client.db('passportTest');
  const collection = db.collection('users');

  let user = await collection.findOne({ email: req.body.username })

  if (user != null) {
    console.log('Este usuario ya existe')
    res.redirect('/signup')
    client.close()
  } else {
    await collection.insertOne({ email: req.body.username, pass: req.body.password })

    let user2 = await collection.findOne({ email: req.body.username })
    console.log(user2)

    client.close()

    res.redirect('/inside');
  }

});

module.exports = router;
