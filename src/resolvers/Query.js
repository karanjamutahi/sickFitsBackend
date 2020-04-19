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
};

module.exports = Query;
