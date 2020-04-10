const { forwardTo } =  require('prisma-binding');  //Use forwardTo for queries that are exactly similar to whats on Prisma

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
};

module.exports = Query;
