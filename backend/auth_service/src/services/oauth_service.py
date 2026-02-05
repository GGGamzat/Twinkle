import httpx
from typing import Dict, Any
from fastapi import HTTPException

from src.services.auth_service import AuthService
from src.config import settings

class OAuthService:
    def __init__(self, auth_service: AuthService):
        self.auth_service = auth_service
    
    async def handle_google_oauth(self, token: Dict[str, Any]) -> Dict[str, Any]:
        user_info = token.get('userinfo')
        
        if not user_info:
            raise HTTPException(status_code=400, detail="Failed to get user info")
        
        email = user_info.get('email')
        oauth_id = user_info.get('sub')
        
        if not email or not oauth_id:
            raise HTTPException(status_code=400, detail="Invalid user info from Google")

        username = user_info.get('name', email.split('@')[0])
        username = username.replace(' ', '_').lower()
        
        user, tokens = await self.auth_service.authenticate_oauth_user(
            email=email,
            provider="google",
            oauth_id=oauth_id,
            username=username
        )
        
        return {
            "redirect_url": f"{settings.FRONTEND_URL}/oauth/callback?"
                          f"access_token={tokens.access_token}&refresh_token={tokens.refresh_token}"
        }
    
    async def handle_github_oauth(self, token: Dict[str, Any]) -> Dict[str, Any]:
        access_token = token.get('access_token')
        
        if not access_token:
            raise HTTPException(status_code=400, detail="No access token")
        
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {access_token}"}

            resp = await client.get("https://api.github.com/user", headers=headers)
            if resp.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to get user info")
            
            user_info = resp.json()

            resp = await client.get("https://api.github.com/user/emails", headers=headers)
            if resp.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to get emails")
            
            emails = resp.json()
            primary_email = next((e for e in emails if e['primary']), None)
            
            if not primary_email:
                raise HTTPException(status_code=400, detail="No email found")
            
            email = primary_email['email']
            oauth_id = str(user_info['id'])
            username = user_info.get('login', email.split('@')[0])
            
            user, tokens = await self.auth_service.authenticate_oauth_user(
                email=email,
                provider="github",
                oauth_id=oauth_id,
                username=username
            )
            
            return {
                "redirect_url": f"{settings.FRONTEND_URL}/oauth/callback?"
                              f"access_token={tokens.access_token}&refresh_token={tokens.refresh_token}"
            }