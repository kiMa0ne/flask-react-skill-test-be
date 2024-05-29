from flask import Flask, request, jsonify, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from datetime import timedelta

app = Flask(__name__)

CORS(app)

app.config['SECRET_KEY'] = "YrkK3mvjV5T6SHbyf61dPNxjtWlcNbgCrTYUlM10cno="

# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://your_db_user:your_db_password@localhost/your_db_name'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'YrkK3mvjV5T6SHbyf61dPNxjtWlcNbgCrTYUlM10cno='
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(weeks=1)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin@localhost/my_flask_db'

db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(80), unique=False, nullable=False)
    lastName = db.Column(db.String(80), unique=False, nullable=False)
    email = db.Column(db.String(150), unique=False, nullable=False)
    phone = db.Column(db.String(15), unique=False, nullable=True)
    favouriteProduct = db.Column(db.String(80), unique=False, nullable=True)

# def add_mock_data():
    # mock_data = [
    #     {'firstName': 'John', 'lastName': 'Doe', 'phone': '1234567890', 'favouriteProduct': 'Steam Deck', 'email': 'john@example.com'},
    #     {'firstName': 'Don', 'lastName': 'Joe', 'phone': '166667890', 'favouriteProduct': 'Nintendo Switch', 'email': 'email@example.com'},
    #     {'firstName': 'Will', 'lastName': 'Smith', 'phone': '3294823745', 'favouriteProduct': 'Slap-face-automator', 'email': 'will@smith.com'},
    #     {'firstName': 'Papa', 'lastName': 'V', 'phone': '6969696969', 'favouriteProduct': 'COCCO', 'email': 'papa@v.com'},
    #     {'firstName': 'The', 'lastName': 'Rock', 'phone': '575757757', 'favouriteProduct': 'WWE', 'email': 'john@cena.com'},
    #     {'firstName': "John",'lastName': "Doe",'email': "john.doe@example.com",'phone': "123-456-7890",'favouriteProduct': "Apple iPhone"},
    #     {'firstName': "Jane", 'lastName': "Doe", 'email': "jane.doe@example.com", 'phone': "098-765-4321", 'favouriteProduct': "Samsung Galaxy"},
    #     {'firstName': "Bob", 'lastName': "Smith", 'email': "bob.smith@example.com", 'phone': "111-222-3333", 'favouriteProduct': "Google Pixel"}
    # ]

    # for data in mock_data:
    #     customer = Customer(
    #         firstName=data['firstName'],
    #         lastName=data['lastName'],
    #         phone=data['phone'],
    #         favouriteProduct=data['favouriteProduct'],
    #         email=data['email']
    #     )
    #     db.session.add(customer)


    # hashed_password = generate_password_hash('1234', method='pbkdf2:sha256')
    # new_user = User(username='Admin', password=hashed_password)
    # db.session.add(new_user)

    # db.session.commit()

@app.route('/get-customers', methods=['GET'])
@jwt_required()
def getCustomers():
    customers = Customer.query.all()
    return jsonify([{
        'id': customer.id,
        'firstName': customer.firstName,
        'lastName': customer.lastName,
        'email': customer.email,
        'phone': customer.phone,
        'favouriteProduct': customer.favouriteProduct,
    } for customer in customers])

@app.route('/get-customer-by-id/<int:id>', methods=['GET'])
@jwt_required()
def getCustomer(id):
    customer = Customer.query.get(id)
    if not customer:
        return jsonify({'error': 'Customer not found'}), 404
    return jsonify({
        'id': customer.id,
        'firstName': customer.firstName,
        'lastName': customer.lastName,
        'email': customer.email,
        'phone': customer.phone,
        'favouriteProduct': customer.favouriteProduct
    })

@app.route('/update-customer/<int:id>', methods=['PUT'])
@jwt_required()
def updateCustomer(id):
    data = request.get_json()
    customer = Customer.query.get(id)
    if not customer:
        return jsonify({'error': 'Customer not found'}), 404
    if 'firstName' in data:
        customer.firstName = data['firstName']
    if 'lastName' in data:
        customer.lastName = data['lastName']
    if 'phone' in data:
        customer.phone = data['phone']
    if 'favouriteProduct' in data:
        customer.favouriteProduct = data['favouriteProduct']
    if 'email' in data:
        existing_customer = Customer.query.filter_by(email=data['email']).first()
        if existing_customer and existing_customer.id != id:
            return jsonify({'error': 'A customer with this email already exists'}), 400
        customer.email = data['email']
    db.session.commit()
    return jsonify({
        'id': customer.id,
        'firstName': customer.firstName,
        'lastName': customer.lastName,
        'email': customer.email,
        'phone': customer.phone,
        'favouriteProduct': customer.favouriteProduct
    })

@app.route('/create-customer', methods=['POST'])
@jwt_required()
def addCustomer():
    data = request.get_json()

    # Check if the data is valid
    if not data or 'firstName' not in data or 'email' not in data:
        return jsonify({'error': 'Invalid data'}), 400

    # Check if a customer with the same email already exists
    if Customer.query.filter_by(email=data['email']).first():
        return jsonify({
                'error': 'A customer with this email already exists',
                'fieldError': 'email'
        }), 400

    newCustomer = Customer(
        firstName = data['firstName'],
        lastName = data['lastName'],
        email = data['email'],
        phone = data['phone'],
        favouriteProduct = data['favouriteProduct']
    )

    db.session.add(newCustomer)
    db.session.commit()
    return jsonify({
        'id': newCustomer.id,
        'firstName': newCustomer.firstName,
        'lastName': newCustomer.lastName,
        'email': newCustomer.email,
        'phone': newCustomer.phone,
        'favouriteProduct': newCustomer.favouriteProduct
    }), 201

@app.route('/delete-customer/<int:id>', methods=['DELETE'])
@jwt_required()
def deleteCustomer(id):
    customer = Customer.query.get(id)
    if not customer:
        return jsonify({'error': 'Customer not found'}), 404
    db.session.delete(customer)
    db.session.commit()
    customers = Customer.query.all()
    return jsonify([{
        'id': customer.id,
        'firstName': customer.firstName,
        'lastName': customer.lastName,
        'email': customer.email,
        'phone': customer.phone,
        'favouriteProduct': customer.favouriteProduct,
    } for customer in customers])

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({
        'token': access_token,
        'username': username,
    }), 200

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected_route():
    current_user = get_jwt_identity()
    return jsonify({'message': f'Hello, user {current_user}!'}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # add_mock_data()  # Add the mock data
    app.run(debug=True)