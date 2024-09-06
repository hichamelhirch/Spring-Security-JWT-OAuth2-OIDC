Voici un exemple de fichier `README.md` pour votre projet **Spring Security JWT OAuth2 OIDC** :

---

# Spring Security JWT OAuth2 OIDC

This repository contains a simple Spring Boot application demonstrating how to secure REST APIs using **Spring Security** with **JWT** (JSON Web Token) and **OAuth2** with **OpenID Connect (OIDC)**. The project uses RSA keys to sign and verify JWTs, and implements role-based authorization using in-memory users.

## Table of Contents
- [Features](#features)
- [Technologies](#technologies)
- [Getting Started](#getting-started)
- [Endpoints](#endpoints)
- [Running the Application](#running-the-application)
- [Contributing](#contributing)
- [License](#license)

## Features
- **JWT Authentication**: Implements user authentication with JWT, generating access and refresh tokens.
- **OAuth2 and OIDC Integration**: Demonstrates integration with OAuth2 and OpenID Connect for secure authentication.
- **Role-based Authorization**: Protects specific API endpoints based on user roles (`USER`, `ADMIN`).
- **RSA Key Pair**: Uses RSA public/private keys to sign and verify JWTs.
- **In-memory User Authentication**: Users are stored in memory for easy testing and prototyping.
- **Stateless Session**: Uses stateless JWT-based authentication, with session management disabled.

## Technologies
- [Spring Boot](https://spring.io/projects/spring-boot)
- [Spring Security](https://spring.io/projects/spring-security)
- [JWT (JSON Web Token)](https://jwt.io/)
- [OAuth2 and OIDC](https://openid.net/connect/)
- [RSA Public/Private Keys](https://en.wikipedia.org/wiki/RSA_(cryptosystem))

## Getting Started

### Prerequisites
- Java 17 or later
- Maven 3.6+ or Gradle (if using the wrapper, no need to install)
- Basic knowledge of Spring Boot and Security concepts

### Installation
1. **Clone the repository**:
    ```bash
    git clone https://github.com/your-username/Spring-Security-JWT-Oauth2-OIDC.git
    cd Spring-Security-JWT-Oauth2-OIDC
    ```

2. **Install dependencies**:
    If using Maven:
    ```bash
    mvn clean install
    ```

    If using Gradle:
    ```bash
    ./gradlew build
    ```

3. **Configure RSA Keys**:
   Place your RSA public and private keys in the `application.properties` file under the prefix `rsa`. Example:
   ```properties
   rsa.publicKey=your_public_key_here
   rsa.privateKey=your_private_key_here
   ```

4. **Run the application**:
    If using Maven:
    ```bash
    mvn spring-boot:run
    ```

    If using Gradle:
    ```bash
    ./gradlew bootRun
    ```

## Endpoints

### `/token`
- **POST**: Authenticate a user using `username` and `password`. It will return an access token and, optionally, a refresh token.
- Example request:
    ```bash
    curl -X POST "http://localhost:8080/token?username=user1&password=1234&grantType=password"
    ```

### `/products`
- **GET**: A protected endpoint that returns product information. Requires `ADMIN` role to access.
- Example request with access token:
    ```bash
    curl -X GET "http://localhost:8080/products" -H "Authorization: Bearer <access_token>"
    ```

## Running the Application

1. **Start the application**: Follow the [Installation](#installation) steps.
2. **Testing Authentication and Authorization**:
    - Use the `/token` endpoint to get a JWT token.
    - Use the JWT token to access the `/products` endpoint, which requires the `ADMIN` role.
    
3. **In-memory Users**:  
   The following users are pre-configured in memory:
   - `user1` (password: `1234`, role: `USER`)
   - `admin` (password: `admin`, role: `ADMIN`)

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any changes you'd like to contribute.

### How to contribute:
1. Fork this repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes.
4. Push your changes to your fork.
5. Open a pull request against the `main` branch of this repository.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

