from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List, Optional
from pydantic import BaseModel
import uuid

from app.database import get_db
from app.models.user import User
from app.models.contact import Contact
from app.api.auth import get_current_user

router = APIRouter()

class UserResponse(BaseModel):
    id: str
    username: str
    full_name: Optional[str]
    profile_picture: Optional[str]

    class Config:
        orm_mode = True

class ContactCreate(BaseModel):
    contact_id: str
    alias: Optional[str] = None

class ContactResponse(BaseModel):
    id: str
    contact_user: UserResponse
    alias: Optional[str]
    created_at: str

    class Config:
        orm_mode = True
        # Helper to serialize datetime
        json_encoders = {
            # datetime: lambda v: v.isoformat() 
        }

@router.get("/search", response_model=List[UserResponse])
async def search_users(query: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    if len(query) < 3:
        return []
    
    # Search by username or email, excluding self
    stmt = select(User).where(
        (User.username.ilike(f"%{query}%") | User.email.ilike(f"%{query}%")) & 
        (User.id != current_user.id)
    ).limit(10)
    
    result = await db.execute(stmt)
    users = result.scalars().all()
    
    return [
        UserResponse(
            id=str(u.id),
            username=u.username,
            full_name=u.full_name,
            profile_picture=u.profile_picture
        ) for u in users
    ]

@router.post("/", response_model=ContactResponse)
async def add_contact(contact_data: ContactCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Check if user exists
    try:
        contact_uuid = uuid.UUID(contact_data.contact_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    result = await db.execute(select(User).where(User.id == contact_uuid))
    target_user = result.scalars().first()
    
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if target_user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot add yourself")

    # Check if already a contact
    stmt = select(Contact).where(
        (Contact.owner_id == current_user.id) & 
        (Contact.contact_id == target_user.id)
    )
    existing = await db.execute(stmt)
    if existing.scalars().first():
        raise HTTPException(status_code=400, detail="User already in contacts")

    new_contact = Contact(
        owner_id=current_user.id,
        contact_id=target_user.id,
        alias=contact_data.alias
    )
    
    db.add(new_contact)
    await db.commit()
    await db.refresh(new_contact)
    
    # Eager load for response
    # In async sqlalchemy, accessing relationships requires explicit loading or careful handling
    # For simplicity, we construct response manually or rely on lazy loading if session is open (but async is tricky)
    # Let's just return the data we have
    
    return ContactResponse(
        id=str(new_contact.id),
        contact_user=UserResponse(
            id=str(target_user.id),
            username=target_user.username,
            full_name=target_user.full_name,
            profile_picture=target_user.profile_picture
        ),
        alias=new_contact.alias,
        created_at=new_contact.created_at.isoformat()
    )

@router.get("/", response_model=List[ContactResponse])
async def get_contacts(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Join to get user details
    stmt = select(Contact, User).join(User, Contact.contact_id == User.id).where(Contact.owner_id == current_user.id)
    
    result = await db.execute(stmt)
    rows = result.all() # List of (Contact, User) tuples
    
    contacts = []
    for contact, user in rows:
        contacts.append(ContactResponse(
            id=str(contact.id),
            contact_user=UserResponse(
                id=str(user.id),
                username=user.username,
                full_name=user.full_name,
                profile_picture=user.profile_picture
            ),
            alias=contact.alias,
            created_at=contact.created_at.isoformat()
        ))
        
    return contacts
