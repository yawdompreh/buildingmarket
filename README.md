# buildingmarket

BuildChain: a global building-materials marketplace plus houses and land for sale.

- Suppliers upload products, houses and land with photos and videos, and can edit or delete their posts.
- Buyers pay cash on delivery or by Visa, Mastercard or Discover. The platform takes a 5% commission.
- An admin can edit and delete every post.

## Run

Requires Node 22.13+.

1. Create a `.env` file (git-ignored) with `ADMIN_EMAIL=...` and `ADMIN_PASSWORD=...`.
2. `npm start`
3. Open http://localhost:3000

Card processing is simulated; connect a real payment provider (see `authorizeCard` in `server.js`) before going live.
