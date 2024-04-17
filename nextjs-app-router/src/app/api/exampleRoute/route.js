import {validateAccessToken} from "@propelauth/nextjs/server"


export const GET = async () => {
    const user = await validateAccessToken("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjQ1OWFjNTRhLTM2ZjEtNGMxYy1hYThjLTU3Y2ZiMWRkYTIyNyJ9.eyJzdWIiOiIxNGY3ZWExYi1kZGZmLTQ2MzMtOGRmMi1lOTZkNjQxNDNkMGUiLCJpYXQiOjE3MTMyODI0MzcsImV4cCI6MTcxMzM2ODgzNywidXNlcl9pZCI6IjE0ZjdlYTFiLWRkZmYtNDYzMy04ZGYyLWU5NmQ2NDE0M2QwZSIsImlzcyI6Imh0dHBzOi8vNDc0OTA4MDQ0OTgucHJvcGVsYXV0aHRlc3QuY29tIiwiZW1haWwiOiJwYXVsQHByb3BlbGF1dGguY29tIiwiZmlyc3RfbmFtZSI6IlBhdWwiLCJsYXN0X25hbWUiOiJWYXR0ZXJvdHQiLCJvcmdfaWRfdG9fb3JnX21lbWJlcl9pbmZvIjp7fSwibG9naW5fbWV0aG9kIjp7ImxvZ2luX21ldGhvZCI6ImdlbmVyYXRlZF9mcm9tX2JhY2tlbmRfYXBpIn19.iDIOeUwmqaTLM32PfbkgoimU4yrkWOJc8IwdZMRR7F5kHOSRtTm6IKwihdxf8aGYRWw-s4EQujmav977j6zzdXAQg4ZEntLjQ-DprNjP9p-xd_3epsPThaOfV2QStXwUKk_USmUfCwy8kjiMLgYn2nrRakTtXXEgM3iKD8j0yiJ8hzK9FN-AyGnOk3BtUNrxGDwjfriVccoS3R2uAF5myYxuPcvHGZKe5teN1BW4Bxe7rt48UQ75dHHpUH53HNfvJBeO8L4eDT6RppsAdfZNpwB4agLOdJfyCV77-D9kiAJdTvBAP0MqBWbFGITSij8lHFz_x39WVBjNgorc5LUIFw")
    console.log(user)
    
    if (user) {
        return Response.json({ user })
    } else {
        return Response.json({ "error": "error" })
    }
}