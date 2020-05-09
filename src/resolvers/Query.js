const { forwardTo } =  require('prisma-binding');  //Use forwardTo for queries that are exactly similar to whats on Prisma
const { hasPermission } = require('../utils');

const Query = {
    items: forwardTo('db'),
    item: forwardTo('db'),
    itemsConnection: forwardTo('db'),
    async me (parent, args, ctx, info) {
        if(!ctx.request.userID) {
            return null;
        }

        return ctx.db.query.user(
            {
                where: {
                    id: ctx.request.userID
                }
            }
        , info);    
    },
    user: forwardTo('db'),
    async users(parent, args, ctx, info) {
        //1. Check if they're logged in
        if(!ctx.request.userID) {
            throw new Error("You need to be logged in to do that");
        }
        //2. Check if user has permissions to query all the users

        hasPermission(ctx.request.user , ["ADMIN", "PERMISSIONUPDATE"]);
        //3. If they do, query all the users
        return ctx.db.query.users({}, info);
    },

    async order(parent, args, ctx, info) {
        //1. Make Sure they are logged in
        if(!ctx.request.userID) throw new Error("You need to be logged in to do that");

        //2. Query the current order
        const order = await ctx.db.query.order({
            where: {
                id: args.id,
            }
        }, info);

        //3. Check if they have the permission to see this order
        const ownsOrder = order.user.id === ctx.request.userID;
        const hasPermissionToSeeOrder = ctx.request.user.permissions.includes('ADMIN');
        if(!ownsOrder || !hasPermissionToSeeOrder) throw new Error("You can't do that");
        
        //4. Return the order
        return order;
    },

    async orders(parent, args, ctx, info) {
        //1. Check if user is logged in
        if(!ctx.request.userID) throw new Error("You must be logged in to do that");

        //2. Check if ID has been supplied
        let id = ctx.request.userID;
        if(args.id) {
            if (!ctx.request.user.permissions.includes('ADMIN')) throw new Error("You can't do that");
            id  = args.id ;
        }

        //3. Query db for the orders
        const orders = await ctx.db.query.orders({
            where: {
                user: {
                    id,
                }
            }, 
            orderBy: 'createdAt_DESC',
        }, info);

        //4. Return orders
        return orders;
    }
};

module.exports = Query;
