const { response } = require("express");
const Usuario = require("../models/Usuario");
const bcrypt = require('bcryptjs')
const {generarJWT} = require('../helpers/jwt')

const crearUsuario = async (req, resp = response) => {

  const {email,name,password} = req.body;
  
  try {
    //Verificar el email
    const usuario = await Usuario.findOne({email});

    if(usuario){
        return resp.status(400).json({
            ok: false,
            msg: 'El usuario ya existe con ese email'
        });
    }

    //Crear usuario con el modelo
    const dbUser = new Usuario(req.body);


    //Hashear la contraseña
    const salt = bcrypt.genSaltSync();
    dbUser.password = bcrypt.hashSync(password, salt);

    //Generar el JWT

    const token = await generarJWT(dbUser.id, name);

    //Crear usuario de BD
    await dbUser.save();

    //Generar respuesta exitosa
    return resp.status(201).json({
        ok: true,
        uid: dbUser.id,
        name,
        email,
        token
    });
      
  } catch (error) {
    return resp.status(500).json({
        ok: false,
        msg: "Por favor, hable con el admin",
      });
  }
};

const loginUsuario = async (req, resp = response) => {

    const {email,password} = req.body;

    try {
        const dbUser = await Usuario.findOne({email});
        if(!dbUser){
            return resp.status(400).json({
                ok: false,
                msg: 'El correo no existe'
            });
        }

            //Confirmar si el password hace match
            const validPassword = bcrypt.compareSync(password, dbUser.password);
            if(!validPassword){
                return resp.status(400).json({
                    ok: false,
                    msg: 'El password no es válido'
                });
            }

            //Generar JWT
            const token = await generarJWT(dbUser.id, dbUser.name);

            //Respuesta del servicio

            return resp.json({
                ok: true,
                uid: dbUser.id,
                name: dbUser.name,
                email: dbUser.email,
                token
            })
        
    } catch (error) {
        console.log(error);
        return resp.status(500).json({
            ok: false,
            msg: "Por favor, hable con el admin",
          });
        
    }

};

const revalidarToken = async (req, resp = response) => {
    const {uid} = req;
    const dbUser = await Usuario.findById(uid);

    const token = await generarJWT(uid, dbUser.name);

    return resp.json({
        ok: true,
        uid,
        name: dbUser.name,
        email: dbUser.email,
        token
    });
};

module.exports = {
  crearUsuario,
  loginUsuario,
  revalidarToken,
};
