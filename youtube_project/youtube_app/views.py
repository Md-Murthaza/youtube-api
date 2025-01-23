from .models import Youtubetoken  
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.shortcuts import redirect, render ,HttpResponse
from django.utils import timezone
from google_auth_oauthlib.flow import Flow
from datetime import timedelta
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from google.oauth2.credentials import Credentials
from django.contrib import messages


@login_required
def youtube_authorization(request):
    credentials_dict = {
        'web': {
            'client_id': settings.YOUTUBE_CLIENT_ID,
            'client_secret': settings.YOUTUBE_CLIENT_SECRET,
            'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
            'token_uri': 'https://oauth2.googleapis.com/token',
            'redirect_uris': [settings.YOUTUBE_REDIRECT_URI],
        }
    }
    try:
        flow = Flow.from_client_config(
            credentials_dict,
            scopes=['https://www.googleapis.com/auth/youtube.readonly','https://www.googleapis.com/auth/youtube.upload','https://www.googleapis.com/auth/youtube.force-ssl']
        )
        flow.redirect_uri = settings.YOUTUBE_REDIRECT_URI
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        request.session['youtube_oauth_state'] = state
        return redirect(auth_url)

    except Exception as e:
        return render(request, 'error.html', {
            'error': f'Authorization failed: {str(e)}'
        })


@login_required
def oauth2callback(request):
    try:
        state = request.session.get('youtube_oauth_state')
        if not state:
            return render(request, 'error.html', {
                'error': 'Missing OAuth state. Please try again.'
            })

        credentials_dict = {
            'web': {
                'client_id': settings.YOUTUBE_CLIENT_ID,
                'client_secret': settings.YOUTUBE_CLIENT_SECRET,
                'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                'token_uri': 'https://oauth2.googleapis.com/token',
                'redirect_uris': [settings.YOUTUBE_REDIRECT_URI],
            }
        }
        flow = Flow.from_client_config(
            credentials_dict,
            scopes=['https://www.googleapis.com/auth/youtube.readonly','https://www.googleapis.com/auth/youtube.upload','https://www.googleapis.com/auth/youtube.force-ssl'],
            state=state
        )
        flow.redirect_uri = settings.YOUTUBE_REDIRECT_URI
        authorization_response = request.build_absolute_uri()
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials
        
        token, created = Youtubetoken.objects.update_or_create(
            user=request.user,
            defaults={
                'access_token': credentials.token,
                'refresh_token': credentials.refresh_token,
                'expires_at': timezone.make_aware(credentials.expiry)
            }
        )
        return redirect('youtube_dashboard')

    except Exception as e:
        return render(request, 'error.html', {
            'error': f'Callback failed: {str(e)}'
        })


@login_required
def youtube_dashboard(request):
    return render(request, 'dashboard.html')


@login_required
def upload_video(request):
    if request.method == 'POST' and request.FILES.get('video_file'):
        video_file = request.FILES['video_file']
        title = request.POST.get('title', 'Untitled Video')
        description = request.POST.get('description', 'No description')

        try:
            token = Youtubetoken.objects.get(user=request.user)
            if token.is_expired():
                messages.error(request, 'Token expired. Please reauthenticate.', extra_tags='danger')
                return redirect('youtube_authorization')
            
            credentials = Credentials(
                token=token.access_token,
                refresh_token=token.refresh_token,
                token_uri='https://oauth2.googleapis.com/token',
                client_id=settings.YOUTUBE_CLIENT_ID,
                client_secret=settings.YOUTUBE_CLIENT_SECRET,
            )
            youtube = build('youtube', 'v3', credentials=credentials)

            media = MediaFileUpload(video_file.temporary_file_path(), chunksize=-1, resumable=True)
            request_body = {
                'snippet': {'title': title, 'description': description},
                'status': {'privacyStatus': 'private'}
            }

            upload_request = youtube.videos().insert(part='snippet,status', body=request_body, media_body=media)
            response = upload_request.execute()
            return render(request, 'upload_sucess.html', {
                'video_id': response['id'],
                'title': title,
                'description': description,
            })
        except Youtubetoken.DoesNotExist:
            return render(request, 'error.html', {'error': 'YouTube authentication required.'})
        except Exception as e:
            return render(request, 'error.html', {'error': f'Upload failed: {str(e)}'})

    return render(request, 'upload.html')


#listing videos of my youtube page

@login_required
def list_videos(request):
    try:
        token = Youtubetoken.objects.get(user=request.user)
        if token.is_expired():
            return render(request, 'error.html', {'error': 'Token expired. Please reauthenticate.'})
        
        youtube = build(
            'youtube', 'v3',
            credentials=Credentials(
                token=token.access_token,
                refresh_token=token.refresh_token,
                token_uri='https://oauth2.googleapis.com/token',
                client_id=settings.YOUTUBE_CLIENT_ID,
                client_secret=settings.YOUTUBE_CLIENT_SECRET,
            )
        )
        request = youtube.search().list(
            part='snippet',
            forMine=True,
            type='video',
            maxResults=10  # Adjust as needed
        )
        response = request.execute()

        videos = response.get('items', [])
        return render(request, 'list_videos.html', {'videos': videos})

    except Exception as e:
        return render(request, 'error.html', {'error': f'Failed to fetch videos: {str(e)}'})


#edit description of my youtube videos
@login_required
def edit_video_description(request, video_id):
    if request.method == 'POST':
        new_description = request.POST.get('description', '')
        try:
            token = Youtubetoken.objects.get(user=request.user)
            if token.is_expired():
                return render(request, 'error.html', {'error': 'Token expired. Please reauthenticate.'})
            
            youtube = build(
                'youtube', 'v3',
                credentials=Credentials(
                    token=token.access_token,
                    refresh_token=token.refresh_token,
                    token_uri='https://oauth2.googleapis.com/token',
                    client_id=settings.YOUTUBE_CLIENT_ID,
                    client_secret=settings.YOUTUBE_CLIENT_SECRET,
                )
            )
            request = youtube.videos().update(
                part='snippet',
                body={
                    'id': video_id,
                    'snippet': {
                        'description': new_description
                    }
                }
            )
            request.execute()

            return render(request, 'success.html', {'message': 'Video description updated successfully.'})
        except Exception as e:
            return render(request, 'error.html', {'error': f'Failed to update description: {str(e)}'})
    return render(request, 'edit_description.html', {'video_id': video_id})
