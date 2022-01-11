const Sequelize = require('sequelize');
const { STRING } = Sequelize;
const config = {
  logging: false
};
const jwt = require('jsonwebtoken');
const bcrypt = require("bcrypt");


if(process.env.LOGGING){
  delete config.logging;
}
const conn = new Sequelize(process.env.DATABASE_URL || 'postgres://localhost/acme_db', config);

const User = conn.define('user', {
  username: STRING,
  password: STRING
});

User.prototype.generateToken = async function () {
  try {
    const token = await jwt.sign({ id: this.id }, process.env.JWT);
    return { token };
  } catch (err) {
    console.error(err);
  }
};

User.byToken = async function (token) {
  try {
    const payload = await jwt.verify(token, process.env.JWT);
    if (payload) {
      //find user by payload which contains the user id
      const user = await User.findByPk(payload.id);
      return user;
    }
    const error = Error("bad credentials");
    error.status = 401;
    throw error;
  } catch (ex) {
    const error = Error("bad credentials");
    error.status = 401;
    throw error;
  }
};

User.authenticate = async ({ username, password }) => {
  const user = await User.findOne({
    where: {
      username,
    },
  });
  const match = await bcrypt.compare(password, user.password);
  if (match) {
    return user;
  }
  const error = Error("bad credentials");
  error.status = 401;
  throw error;
};

User.addHook('beforeCreate', async(user)=> {
  if(user.changed('password')){
    user.password = await bcrypt.hash(user.password, 3);
  }
});

const syncAndSeed = async()=> {
  await conn.sync({ force: true });
  const credentials = [
    { username: 'lucy', password: 'lucy_pw'},
    { username: 'moe', password: 'moe_pw'},
    { username: 'larry', password: 'larry_pw'}
  ];
  const [lucy, moe, larry] = await Promise.all(
    credentials.map( credential => User.create(credential))
  );
  return {
    users: {
      lucy,
      moe,
      larry
    }
  };
};

module.exports = {
  syncAndSeed,
  models: {
    User
  }
};
