from app.analysis.types import PackageRef

_ROLES: dict[str, dict[str, set[str]]] = {
    "npm": {
        "auth": {
            "jsonwebtoken", "passport", "passport-local", "passport-jwt", "bcrypt", "bcryptjs",
            "express-session", "jose", "next-auth", "argon2", "oauth", "oauth2-server",
        },
        "crypto": {"crypto-js", "node-forge", "jsrsasign", "sjcl", "tweetnacl", "elliptic"},
        "web_framework": {
            "express", "koa", "fastify", "hapi", "@hapi/hapi", "next", "restify", "@nestjs/core", "sails",
        },
        "database": {
            "mongoose", "sequelize", "typeorm", "knex", "pg", "mysql", "mysql2", "mongodb",
            "prisma", "@prisma/client", "redis", "ioredis",
        },
        "serialization": {
            "js-yaml", "yaml", "xml2js", "fast-xml-parser", "handlebars", "ejs", "pug", "mustache",
        },
    },
    "PyPI": {
        "auth": {
            "pyjwt", "python-jose", "authlib", "passlib", "bcrypt", "argon2-cffi", "django-allauth",
            "flask-login", "flask-jwt-extended", "oauthlib",
        },
        "crypto": {"cryptography", "pycryptodome", "pycryptodomex", "pyopenssl", "paramiko", "rsa"},
        "web_framework": {
            "django", "flask", "fastapi", "starlette", "tornado", "aiohttp", "bottle", "pyramid",
            "sanic", "falcon", "werkzeug",
        },
        "database": {
            "sqlalchemy", "psycopg2", "psycopg2-binary", "psycopg", "pymongo", "mysqlclient",
            "pymysql", "redis",
        },
        "serialization": {"pyyaml", "jinja2", "lxml", "xmltodict", "mako"},
    },
}


def role_for(ref: PackageRef) -> str | None:
    name = ref.name.lower()
    for role, names in _ROLES.get(ref.ecosystem, {}).items():
        if name in names:
            return role
    return None