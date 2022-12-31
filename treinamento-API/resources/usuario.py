import resource
from tokenize import String
from flask_restful import Resource, reqparse
from models.usuario import UserModel, UserModel
from flask_jwt_extended import create_access_token, jwt_required, get_jwt
from werkzeug.security import safe_str_cmp
from blacklist import BLACKLIST


atributos = reqparse.RequestParser()
atributos.add_argument('login', type=str, required=True, help='The field login is mandatory')
atributos.add_argument('senha', type=str, required=True, help='The field senha is mandatory')

class User(Resource):
    # /usuarios/{user_id}
    def get(self, user_id):
        user = UserModel.find_user(user_id)
        if user:
            return user.json()
        return {'Message': 'User not found'}, 404       

    @jwt_required()
    def delete(self, user_id):
        user = UserModel.find_user(user_id)
        if user:
            try:
                user.delete_user()
            except:
                {'Message': 'An internal error ocurred trying to delete User.'}, 500
            return {'Message': 'User deleted.'}, 200  
        return {'Message': 'User Not Found'}, 404

class UserRegister(Resource):
    #/cadastro
    def post(self):
        dados = atributos.parse_args()

        if UserModel.find_by_login(dados['login']):
            return {"message": f"The login '{dados['login']}'already exist."}
        
        user = UserModel(**dados)
        user.save_user()
        return {'message': 'User create successfully'}, 201

class UserLogin(Resource):
    
    @classmethod
    def post(cls):
        dados = atributos.parse_args()

        user = UserModel.find_by_login(dados['login'])

        if user and safe_str_cmp(user.senha, dados['senha']):
            token_de_acesso = create_access_token(identity=user.user_id)
            return {'access_token': token_de_acesso}, 200
        return {'Message': 'The Username or password is incorrect.'}, 401


class UserLogout(Resource):

    @jwt_required()
    def post(self):
        jwt_id = get_jwt()['jti']
        BLACKLIST.add(jwt_id)
        return {'message': 'Logged out sucessflully'}