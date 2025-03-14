<div align="center">
  <h1>
    Stripe Webhooks Events to Novu Workflows
  </h1>
</div

This repository contains a simple webhook endpoint that listens for Stripe webhook events and triggers Novu workflows.

Check out the [Integration Guide](https://docs.novu.co/guides/webhooks/stripe) to learn more.

## Deploy

Easily deploy the template to Vercel with the button below. You will need to set the required environment variables in the Vercel dashboard.

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fclerk%2Fnextjs-auth-starter-template&env=CLERK_SECRET_KEY,NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY&envDescription=Your%20Clerk%20application%20keys%2C%20accessible%20from%20dashboard.clerk.com.&envLink=https%3A%2F%2Fgithub.com%2Fclerk%2Fnextjs-auth-starter-template%3Ftab%3Dreadme-ov-file%23running-the-template&demo-url=https%3A%2F%2Fnextjs-auth-starter-template-kit.vercel.app%2F)

## Running Locally

```bash
git clone https://github.com/novuhq/stripe-to-novu-webhooks.git
```

To run the example locally, you need to:    

1. `npm install` the required dependencies.
2. `npm run dev` to launch the development server.

## Learn more

To learn more about Stripe and Novu, check out the following resources:

- [Quickstart: Get started with Novu](https://docs.novu.co/overview)
- [Stripe Documentation](https://docs.stripe.com/)
- [Novu Documentation](https://docs.novu.co)
- [Next.js Documentation](https://nextjs.org/docs)
