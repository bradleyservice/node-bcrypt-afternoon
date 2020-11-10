module.exports = {
    dragonTreasure: async (req, res) => {
        const db = req.app.get('db');
        let firstTreasure = await db.get_dragon_treasure(1)
        res.status(200).send(firstTreasure)
    },
    getUserTreasure: async (req, res) => {
        const db = req.app.get('db');
        let secondTreasure = await db.get_user_treasure([req.session.user.id])
        res.status(200).send(secondTreasure)
    },
    addUserTreasure: async (req, res) => {
        const {treasureURL} = req.body;
        const {id} = req.session.user;
        const db = req.app.get('db');
        let userTreasure = await db.add_user_treasure(treasureURL, id);
        res.status(200).send(userTreasure);
    },
    getAllTreasure: async (req, res) => {
        const db = req.app.get('db');
        let adminTreasure = await db.get_all_treasure();
        res.status(200).send(adminTreasure);
    }
}