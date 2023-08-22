const User = require('../users/users-model')
const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require("../secrets"); // use this secret!

const restricted = (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
  const token = req.headers.authorization
  if(!token) {
    return next({ status: 401, message: 'Token required'})
  }
  jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
    if(err) {
      next({ status: 401, message: 'Token invalid' })
    } else {
      req.decodedToken = decodedToken
      next()
    }
  })
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
  next()
}


const checkUsernameExists = (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
  User.findBy({ username: req.body.username })
    .then(array => {
      if(!array.length) {
        next({ status: 401, message: 'Invalid credentials' })
      } else {
        req.user = array[0]
        next()
      }
    })
    .catch(next)
}


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
  if(req.body.role_name && typeof req.body.role_name === 'string') {
    const roleName = req.body.role_name.trim()
    if(roleName === 'admin') {
      next({ status: 422, message: 'Role name can not be admin' })
    } else if(roleName.length > 32) {
      next({ status: 422, message: 'Role name can not be longer than 32 chars' })
    } else {
      req.body.role_name = roleName
      next()
    }
  } else {
    req.body.role_name = 'student'
    next()
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
