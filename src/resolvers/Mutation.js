const bcrypt = require('bcryptjs');
const jwt =  require('jsonwebtoken');
const { randomBytes } = require('crypto');
const { promisify } = require('util');
const { transport, makeANiceEmail } = require('../../src/mail');
const { hasPermission }  = require('../utils');

const generateJWT = function(userID) {
    return jwt.sign({userId: userID }, process.env.APP_SECRET);
}

const mutations = {
    async createItem(parent, args,ctx, info) {
        if(!ctx.request.userID) {
            throw new Error('You must be logged in to do that');
        }
        //TODO Check if they are logged in
        const item = await ctx.db.mutation.createItem({
            data: {
                user: {
                    connect: {
                        id: ctx.request.userID
                    }
                },
                ...args
            }
        }, info);

        return item;
    },

    updateItem(parent, args, ctx, info) {
        //first take a copy of the updates
        const updates = { ...args };
        //remove id from the updates
        delete updates.id;
        //run update method
        return ctx.db.mutation.updateItem({ 
            data: updates,
            where: {id: args.id},
        }, info);
    },

    async deleteItem(parent, args, ctx, info) {
        const where = {id : args.id};
        //1. find the item
        const item = await ctx.db.query.item({ where }, `{id title}`);
        //2. Check if they own the item
        //TODO
        //3. Delete it
        return ctx.db.mutation.deleteItem({ where }, info);
    },

    async signUp(parent, args, ctx, info) {
        /**Input Data Validation
         * 1. Email
         *  a. Lowercase it
         * 2. Password
         *  a. Make Sure it not a dumb password
         */

        //Email
        args.email = args.email.toLowerCase();
    
        //Password
        //Hash password
        args.password = await bcrypt.hash(args.password, 10);
        //Create the User
        const user = await ctx.db.mutation.createUser({
            data: {
                ...args,
                permissions: { set: ['USER'] },
            }
        }, info);

        //Create a JWT token for them
        const token = generateJWT(user.id);

        //Set a jwt cookie on the response
        ctx.response.cookie('token', token, { 
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 7, //7 day cookie
        });

        //Return user to browser 
        return user;
    },

    async login(parent, args, ctx, info) {
        //Validate email and check for user with that email
        const user =  await ctx.db.query.user({
            where: {
                email: args.email
            }
        });
        if(!user) {
            throw new Error(`Invalid Login details provided`);
        }
        //hash password
        const valid = await bcrypt.compare(args.password, user.password);
        if(!valid) {
            throw new Error(`Invalid Login details provided`);
        }

        //generate jwt token
        const token = generateJWT(user.id);
        
        //set cookie with token
        ctx.response.cookie('token', token , {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 7
        });
        
        //return user
        return user;
    },

    async signout(parent, args, ctx, info) {
        //  1. Check if any user is signed in
        if(!ctx.request.userID) {
            throw new Error("No User signed in. Malice detected");
        }
        ctx.response.clearCookie('token');
        return { message: "Signed Out"}
    },

    async requestReset(parent, args, ctx, info) {
        //1. Check if user exists
        const user =  await ctx.db.query.user(
            { 
                where : {
                    email: args.email,
                }
            });
        if(!user) {
            throw new Error("Can't find user by that email. Please sign up");
        }

        //2. Generate reset token and append it to user
        const resetToken = (await promisify(randomBytes)(30)).toString('hex');
        const resetTokenExpiry = Date.now() + (1000*60*60*1); //1 Hour
        const res = await ctx.db.mutation.updateUser({
            where: {
                id: user.id
            },
            data: {
                resetToken,
                resetTokenExpiry,
            }
        });

        //3. Email them the reset token
        const mailRes = await transport.sendMail({
            from: 'recoverpassword@sickfits.ke',
            to: user.email,
            subject: "Recover your Password",
            html: makeANiceEmail(`Your Password Reset is here!\n\n<a href="${process.env.FRONTEND_URL}/passwordReset/${user.id}/${resetToken}">Click Here to Reset!</a>`)
        }) 
        //4. Return message
        return { message: `${process.env.FRONTEND_URL}/passwordReset/${user.id}/${resetToken}`}
    },

    async resetPassword (parent, args, ctx, info)  {
        // 1. Check if the passwords match
        if(args.password !== args.confirmPassword) {
            throw new Error("Passwords do not match");
        }

        // 2. Check if reset token is legit
        // 3. Make sure its not expired
        const [user] = await ctx.db.query.users({
            where: {
                id: args.id,
                resetToken: args.resetToken,
                resetTokenExpiry_gte: Date.now()  // - (1000 * 60 * 60 * 1) 1 Hour has not yet passed
            }
        });
        if(!user) {
            throw new Error('Invalid or Expired Token. Please try again. If the issue persists contact Support.');
        }

        // 4. Hash their new password
        const password = await bcrypt.hash(args.password, 10);

        // 5. Save new password and remove old token and tokenexpiry
        const updatedUser = await ctx.db.mutation.updateUser({
            where: {
                email: user.email,
            }, 
            data: {
                password,
                resetToken: null,
                resetTokenExpiry: null,
            }
        });
        // 6. Generate jwt
        const token = generateJWT(user.id);
        // 7. Set the token cookie
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 7
        });
        // 8. return new user
        return updatedUser;
    },


    async updatePermissions(parent, args, ctx, info) {
        //check if they're logged in
        if(!ctx.request.userID) {
            throw new Error("You need to be logged in to do that");
        }
        //query the current user
        const user = await ctx.db.query.user({
            where: {
            id:ctx.request.userID
        }}, info);

        //check if they're allowed to do this
        hasPermission(user, ["ADMIN", "PERMISSIONUPDATE"]);

        //update permissions
        console.log(args);
        return ctx.db.mutation.updateUser({
            data: {
                permissions: {
                    set: args.permissions
                }
            },
            where: {
                id: args.where.id
            }
        }, info);

    },

};

module.exports = mutations;