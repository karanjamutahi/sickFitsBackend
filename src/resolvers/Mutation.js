const bcrypt = require('bcryptjs');
const jwt =  require('jsonwebtoken');
const { randomBytes } = require('crypto');
const { promisify } = require('util');
const { transport, makeANiceEmail } = require('../../src/mail');
const { hasPermission }  = require('../utils');
const stripe = require('../stripe');

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
        //1. find the item
        const where = { id : args.id  };
        const item = await ctx.db.query.item({ where }, `{id title user {id} }`);
    
        //2. Check if they own the item
        const ownsItem = item.user.id === ctx.request.userID;
        const hasPermission = ctx.request.user.permissions.some(permission => ["ITEMDELETE", "ADMIN"].includes(permission));

        if(!ownsItem && !hasPermission) {
            throw new Error("You don't have permission to do that");
        }

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

    async addToCart(parent, args, ctx, info) {
        //1. Make sure they're signed in
        const { userID } = ctx.request;
        if(!userID) throw new Error("You must be Logged in to do that");
        
        //2. Query the Users current cart
        const [ existingCartItem ] = await ctx.db.query.cartItems({
            where: {
                user: {
                    id: userID
                },
                item: {
                    id: args.id
                }
            }
        }, info);

        //3. Check if the item is already in the cart
        if(existingCartItem) {
            console.log("This item is already in their cart");
            return ctx.db.mutation.updateCartItem({
                where: {
                    id: existingCartItem.id,
                },
                data: {
                    quantity: existingCartItem.quantity + 1
                }                
            }, info)
        }

        //4. Add the item
        return ctx.db.mutation.createCartItem({
            data: {
                user: {
                    connect:  {
                        id: userID
                    }
                },
                item: {
                    connect: {
                        id: args.id
                    }
                }
            }
        }, info)
    },

    async removeFromCart(parent, args, ctx, info) {
        //1. Find the cartitem
        const CartItem = await ctx.db.query.cartItem({
            where: {
                id: args.id
            }
        }, info);

        if(!CartItem) throw new Error("No Cart Item Found");
        
        //2. Make sure they own the cartitem
        if(CartItem.user.id !== ctx.request.userID) throw new Error("You can't do that! Malice detected");

        //3. Delete the cartitem
        return ctx.db.mutation.deleteCartItem({
            where: {
                id: CartItem.id
            }
        }, info);
    },

    async createOrder(parent, args, ctx, info) {
        //1. Query the current user & make sure they're signed in
        const { userID } = ctx.request;
        if(!userID) throw new Error("You have to be logged in to do that");
        const user = await ctx.db.query.user({ where: {
            id: userID
        }}, `{ 
            id 
            firstname 
            email 
            cart { 
                id 
                quantity 
                item { 
                    title 
                    price 
                    id 
                    description 
                    image 
                } 
            } 
        }`);

        //2. Recalculate total of the price
        const amount = user.cart.reduce((tally, cartItem) => tally + cartItem.item.price * cartItem.quantity, 0);
        console.log(amount);
        
        //3. Create the Stripe Charge
        const charge = await stripe.charges.create({
            amount,
            currency: "USD",
            source: args.token      
        });

        //4. Convert the Cart Items to Order Items
        let OrderItems = user.cart.map(cartItem => {
            const OrderItem = {
                quantity: cartItem.quantity,
                user: { connect: {
                    id: userID
                }},
                ...cartItem.item
            };
            delete OrderItem.id;
            return OrderItem;
        });

        //5. Create the Order
        const Order = ctx.db.mutation.createOrder({
            data: {
                charge: charge.id,
                total: charge.amount,
                items: { create: OrderItems},
                user: {
                    connect: {
                        id: userID
                    }
                },              
        }});

        //6. Clear Users Cart & Delete Cart Items
        const cartItemIDs = user.cart.map(cartItem => cartItem.id);
        await ctx.db.mutation.deleteManyCartItems({
            where: {
                id_in: cartItemIDs,
            }
        });

        //7. Return Order to the Client
        return Order;

    }
};

module.exports = mutations;