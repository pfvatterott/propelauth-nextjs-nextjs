import { UserFromToken } from '@propelauth/nextjs/server'
import { getRouteHandlers } from '@propelauth/nextjs/server/app-router'
import { NextRequest } from 'next/server'

// postLoginRedirectPathFn is optional, but if you want to redirect the user to a different page after login, you can do so here.
const routeHandlers = getRouteHandlers({
    postLoginRedirectPathFn: (req: NextRequest) => {
        return '/'
    },
    getDefaultActiveOrgId: (req: NextRequest, user: UserFromToken) => {
        
        const orgs = user.getOrgs().sort((a, b) => {
            return a.orgName.localeCompare(b.orgName)
        })
        if (orgs.length > 0) {
            return orgs[0].orgId
        } else {
            return undefined
        }
    },
})
export const GET = routeHandlers.getRouteHandler
export const POST = routeHandlers.postRouteHandler