import mongoose from "mongoose";
import bcrypt from "bcrypt";

// Formato del objeto Usuario
const usuarioSchema = new mongoose.Schema({
    nombre: {
        type: String,
        trim: true
    },
    primerApellido: {
        type: String,
        trim: true
    },
    segundoApellido: {
        type: String,
        trim: true
    },
    email: {
        type: String,
        lowercase: true,
        trim: true
    },
    password: {
        type: String
    },
    fechaNacimiento: {
        type: Date
    },
    lugarNacimiento: {
        type: String
    },
    lugarResidencia: {
        type: String
    },
    iconoPerfil: {
        type: String
    },
    biografia: {
        type: String,
        maxlength: 300
    },
    apodo: {
        type: String
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Encriptar password antes de guardar
usuarioSchema.pre("save", async function (next) {
    if (!this.isModified("password") || !this.password) return next();

    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// Método para comparar contraseñas
usuarioSchema.methods.comparePassword = async function (passwordPlano) {
    return await bcrypt.compare(passwordPlano, this.password);
};

// Crear modelo
const Usuario = mongoose.model("Usuario", usuarioSchema);

export default Usuario;