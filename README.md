# Golang + Standard Library + JWT + AWS (EC2 and RDS)

This project is a **RESTful API** built with **Golang**, **using only the Standard Library**. The API provides **Authentication** and **Authorization** functionalities and is designed to interact with a **PostgreSQL** database hosted on **AWS RDS**. The application itself is hosted on an **AWS EC2** instance.

## Features

- **User Authentication**: Secure user **signup** and **login** using hashed passwords. **bcrypt**
- **JWT Authorization**: Secure access to protected routes with JSON Web Tokens. **golang-jwt**
- **RESTful Architecture**: Follows RESTful principles.
- **PostgreSQL Integration**: Data is persisted in a PostgreSQL database hosted on AWS RDS. **pgx driver**
- **Deployment on AWS**: The API is hosted on an AWS EC2 instance with a connection to an RDS PostgreSQL database.


## API Endpoints

### Live at : http://13.61.35.203:8080

### Public Routes

- `GET /hello` - Hello World!
- `GET /users` - Get a list of all users.
- `GET /users/{id}` - Get details of a specific user.
- `POST /signup` - Sign up a user.
- `POST /login` - Authenticate a user and receive a JWT.

### Protected Routes

- `GET /users/profile` - Get the profile of the user. (Authorization)
- `PUT /users/{id}` - Update your user account details. **(only can do it to your own user account)**
- `DELETE /users/{id}` - Delete your user account. **(only can do it to your own user account)**

> **Note**: All protected routes require a valid JWT token to be passed in the `Authorization` header.
## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
