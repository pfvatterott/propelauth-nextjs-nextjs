import { UserFromToken } from '@propelauth/nextjs/server'
import { getRouteHandlers } from '@propelauth/nextjs/server/app-router'
import { NextRequest } from 'next/server'
import { cookies } from 'next/headers'

// postLoginRedirectPathFn is optional, but if you want to redirect the user to a different page after login, you can do so here.
const routeHandlers = getRouteHandlers({
    postLoginRedirectPathFn: (req: NextRequest) => {
        return '/'
    },
    getDefaultActiveOrgId: (req: NextRequest, user: UserFromToken) => {
        const cookieStore = cookies()
        const orgId = cookieStore.get('__pa_return_to_path')?.value.split('orgId=')[1]
        return orgId
    },
})
export const GET = routeHandlers.getRouteHandler
export const POST = routeHandlers.postRouteHandler


