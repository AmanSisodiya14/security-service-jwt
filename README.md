# MetaSetu IoT Security Service

A Spring Boot-based JWT authentication and security service designed for IoT platforms. This service provides secure token generation, validation, and refresh capabilities with encryption support for IoT device authentication.

## 🚀 Features

- **JWT Token Management**: Generate, validate, and refresh JWT tokens 
- **Token Encryption**: AES encryption for enhanced security
- **RESTful API**: Clean REST endpoints for authentication operations 
- **Actuator Support**: Health checks and monitoring endpoints
- **CORS Configuration**: Cross-origin resource sharing support

## 🛠️ Technology Stack

- **Java 17**: Latest LTS version
- **Spring Boot 3.2.5**: Modern Spring framework 
- **JWT (JSON Web Tokens)**: Token-based authentication 
- **Lombok**: Code generation and boilerplate reduction

## 📋 Prerequisites

- Java 17 or higher
- Maven 3.6+ 
- PostgreSQL (optional, for persistent storage)

## 🚀 Quick Start

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd metasetu-iot-security
   ```

2. **Build the application**
   ```bash
   mvn clean install
   ```

3. **Run the application**
   ```bash
   mvn spring-boot:run
   ```

   The application will start on `http://localhost:8081`

### Environment Variables

Configure the following environment variables (or use the defaults):

```bash
# Server Configuration
SERVER_PORT=8081

# JWT Configuration
JWT_KEY=your-secret-jwt-key
TOKEN_EXPIRATION_TIME=86400000  # 24 hours in milliseconds
REFRESH_TOKEN_EXPIRATION_TIME=604800000  # 7 days in milliseconds

# Security Configuration
SECURITY_ALGORITHM_NAME=AES
SECURITY_TRANSFORMATION=AES
SECURITY_IV=your-iv-key
SECURITY_KEY=your-encryption-key
```
 
## 📚 API Documentation

### Base URL
```
http://localhost:8081/api/authservice
```

### Endpoints

#### 1. Generate JWT Token
**POST** `/v1/auth/jwt`

Generate access and refresh tokens for authentication.

**Request Body:**
```json
{
  "userId": "device123",
  "deviceId": "iot-device-001"
}
```

**Response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "tokenType": "Bearer"
}
```

#### 2. Validate JWT Token
**GET** `/v1/auth/jwt/validate`

Validate an existing JWT token.

**Headers:**
```
Authorization: Bearer <your-jwt-token>
```

**Response:**
```
Token validated successfully.
```

**Response Headers (Claims):**
When a token is validated, the JWT claims are extracted and included as HTTP response headers. These claims contain user/device information and can be used by downstream services for authorization and context.

```
userId: device123
deviceId: iot-device-001
role: device
exp: 1712345678
iat: 1712259278
...
```

**Note:** The actual claims depend on what was included when the token was generated. Common claims include `userId`, `deviceId`, `role`, `exp` (expiration), and `iat` (issued at).

#### Encrypted Claims in JWT

Instead of storing user/device information as plain claims in the JWT, this service encrypts the entire claims map and stores it as a single claim called `claims`. This approach enhances security by ensuring sensitive information is not visible in the JWT payload.

**Example JWT Payload:**
```json
{
  "claims": "i8Uuzc7TJdoNwgTcLM5DUn0e13Eysmwv9cS8U6w16MG+dmGw+eCjbIJYfgtIKQAw34yb1N2+1oAn916UIUF32EHa9j2mBnHTeqCiT84G0Id/LCfGZdFW+OPdOIwISTECDNwRRTMjtP+EzrI+O9WoR0o7cLi+avLSDJzqLws9d1WbYqj2PDvXnOpzITvvB9HEPBEudodLQ/EMIx8re0OK88x8gB0ljzbBE/ueCPYheAY=",
  "iat": 1754039490,
  "exp": 1754039520
}
```

- The `claims` field contains the **encrypted claims map**.
- Only services with the decryption key can access the original claims.
- Standard JWT fields like `iat` and `exp` are still present.

**Note:** When validating a token, the service will decrypt the `claims` field and use the resulting map for authorization and context.

#### 3. Refresh JWT Token
**GET** `/v1/auth/jwt/refresh/token`

Generate a new access token using a refresh token.

**Headers:**
```
Authorization: Bearer <your-refresh-token>
```

**Response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "tokenType": "Bearer"
}
```

## 🔧 Configuration

### Application Properties

The application uses the following configuration in `application.yml`:

```yaml
server:
  port: 8081

jwt:
  key: your-jwt-secret
  token:
    expiration-time: 86400000  # 24 hours
    refresh-token-expiration-time: 604800000  # 7 days

security:
  algorithm:
    name: AES
    transformation: AES
    iv: your-iv-key
    key: your-encryption-key
```

 
## 📊 Monitoring

The application includes Spring Boot Actuator for monitoring:

- **Health Check**: `http://localhost:8081/actuator/health`
- **Metrics**: `http://localhost:8081/actuator/metrics`
- **Info**: `http://localhost:8081/actuator/info`

## 🔒 Security Features

- **AES Encryption**: Data encryption for sensitive information
- **JWT Token Security**: Secure token generation and validation
- **CORS Configuration**: Cross-origin resource sharing support
- **Exception Handling**: Comprehensive error handling and logging
- **Input Validation**: Request validation and sanitization

## 📁 Project Structure

```
src/
├── main/
│   ├── java/com/metasetu/platform/jwt/
│   │   ├── config/
│   │   │   └── CorsConfig.java
│   │   ├── controller/
│   │   │   └── TokenController.java
│   │   ├── entity/
│   │   │   ├── IotResponse.java
│   │   │   └── JwtResponse.java
│   │   ├── exception/
│   │   │   └── IotExceptionHandler.java
│   │   ├── security/
│   │   │   └── EncryptionService.java
│   │   ├── service/
│   │   │   ├── IJwtService.java
│   │   │   └── JwtService.java
│   │   └── SecurityServiceApplication.java
│   └── resources/
│       └── application.yml
└── test/
    └── java/com/metasetu/platform/jwt/
        └── SecurityServiceApplicationTests.java
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Contact the development team
- Check the documentation

## 🔄 Version History

- **v0.0.1-SNAPSHOT**: Initial release with JWT authentication and IoT security features

---

**MetaSetu IoT Security Service** - Secure authentication for IoT platforms
