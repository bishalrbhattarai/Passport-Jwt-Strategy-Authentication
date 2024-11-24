const express = require("express");
const app = express();
const { sequelize: db, User } = require("./models");
const passport = require("passport");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

app.use(express.json());
app.use(
  cors({
    origin: ["*"],
  })
);

app.use(passport.initialize());
require("./config/passport");

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

app.post("/login", async (req, res) => {
  try {
    const foundUser = (
      await User.findOne({
        where: {
          username: req.body.username,
        },
      })
    ).dataValues;

    if (!foundUser) {
      return res.status(404).json({
        success: false,
        message: "such user doesnot exist",
      });
    }

    const validPassport = await bcrypt.compareSync(
      req.body.password,
      foundUser.hash
    );

    if (!validPassport) {
      return res.status(404).json({
        success: false,
        message: "password is invalid not matching",
      });
    }

    const token = jwt.sign(
      {
        id: foundUser.id,
      },
      "secret_key",
      {
        expiresIn: "1d",
      }
    );

    return res.status(200).json({
      success: true,
      user: { ...foundUser, hash: null },
      token: `Bearer ${token}`,
      expires: "1d",
    });
  } catch (error) {
    console.log(error);
  }
});

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

app.listen(3000, async () => {
  console.log(`http://localhost:3000`);
  await db.authenticate();
  console.log("Connected");
});
