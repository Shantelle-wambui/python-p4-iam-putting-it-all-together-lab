from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from config import db, bcrypt


class User(db.Model, SerializerMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)

    # allow NULL so tests can create a user without setting a password
    _password_hash = db.Column(db.String)

    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # Relationship: a user has many recipes
    recipes = db.relationship(
        "Recipe",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    # Don't expose password hash or circular refs
    serialize_rules = ("-recipes.user", "-_password_hash")

    # ---------------- Password helpers ---------------- #
    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")

    @password_hash.setter
    def password_hash(self, password):
        """Hash the plain password and store it."""
        self._password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def authenticate(self, password):
        """Return True if provided password matches stored hash."""
        return (
            self._password_hash
            and bcrypt.check_password_hash(self._password_hash, password)
        )

    # ---------------- Validations ---------------- #
    @validates("username")
    def validate_username(self, key, username):
        if not username:
            raise ValueError("Username is required")

        existing = User.query.filter(
            User.username == username, User.id != self.id
        ).first()
        if existing:
            raise ValueError("Username must be unique")
        return username

    def __repr__(self):
        return f"<User {self.username}>"


class Recipe(db.Model, SerializerMixin):
    __tablename__ = "recipes"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    # allow NULL so tests can create recipe without a user
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    user = db.relationship("User", back_populates="recipes")

    serialize_rules = ("-user.recipes",)

    # ---------------- Validations ---------------- #
    @validates("title")
    def validate_title(self, key, value):
        if not value or not value.strip():
            raise ValueError("Title is required")
        return value

    @validates("instructions")
    def validate_instructions(self, key, value):
        if not value or not value.strip():
            raise ValueError("Instructions are required")
        if len(value.strip()) < 50:
            raise ValueError("Instructions must be at least 50 characters long")
        return value

    def __repr__(self):
        return f"<Recipe {self.title}>"