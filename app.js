const express = require("express");
const app = express();
const { sequelize: db, User } = require("./models");
const passport = require("passport");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
app.use(cors());
app.use(express.json());
app.use(passport.initialize());

require("./config/passport")(passport);

async function genPass(password) {
  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(password, salt);

  const obj = {};
  obj.salt = salt;
  obj.hash = hash;
  return obj;
}

app.get(
  "/protected",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    try {
      res.json({
        success: true,
      });
    } catch (error) {
      console.log(error);
    }
  }
);

app.post("/register", async (req, res) => {
  try {
    const saltHash = await genPass(req.body.password);
    const newUser = await User.create({
      username: req.body.username,
      salt: saltHash.salt,
      hash: saltHash.hash,
    });

    if (newUser) {
      const signedToken = jwt.sign(
        {
          sub: newUser.id,
        },
        "secret_key",
        {
          expiresIn: "1d",
        }
      );

      return res.json({
        success: true,
        token: `Bearer ${signedToken}`,
        user: newUser,
        expires: "1d",
      });
    } else {
      throw new Error("Something went wrong");
    }
  } catch (error) {
    console.log(error);
    return res.json({
      success: false,
      error,
    });
  }
});

app.post("/login", (req, res) => {});

app.listen(3000, async () => {
  console.log(`http://localhost:3000`);
  await db.authenticate();
  console.log("Connected");
});
