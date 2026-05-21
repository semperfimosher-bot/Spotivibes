const { z } = require("zod");

const registerSchema = z.object({
  firstName: z.string().min(1).max(50),
  lastName: z.string().min(1).max(50),
  email: z.string().email().max(255),
  password: z.string().min(6).max(100),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});


const playlistNameSchema = z.object({
  name: z.string().trim().min(1).max(80)
});

const playlistSaveSchema = z.object({
  name: z.string().trim().min(1).max(80),
  query: z.string().trim().max(120).optional(),
  songs: z.array(z.object({
    id: z.number().int().positive()
  })).max(200)
});

const idParamSchema = z.object({
  id: z.coerce.number().int().positive()
});

module.exports = {
  registerSchema,
  loginSchema,
  playlistNameSchema,
  playlistSaveSchema,
  idParamSchema
};