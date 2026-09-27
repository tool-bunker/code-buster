import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/fastapi_quality_rules.dart';
import 'package:test/test.dart';

void main() {
  List<Finding> run(
    String id,
    Map<String, String> sources, {
    Set<String> changedPaths = const <String>{},
    bool changedMode = false,
  }) => FastApiQualityRule(id)
      .analyze(
        RuleContext(
          config: AnalysisConfig(
            root: '.',
            frameworks: const <String>{'fastapi'},
            changedBase: changedMode ? 'HEAD~1' : '',
          ),
          sources: sources,
          language: 'repository',
          changedPaths: changedPaths,
        ),
      )
      .toList();

  test('every FastAPI rule has executable metadata', () {
    expect(fastApiQualityRuleIds, hasLength(25));
    expect(fastApiQualityRuleMetadata.keys, containsAll(fastApiQualityRuleIds));
    for (final String id in fastApiQualityRuleIds) {
      expect(fastApiQualityRuleMetadata[id]!.frameworks, contains('fastapi'));
      expect(fastApiQualityRuleMetadata[id]!.languages, contains('python'));
    }
  });

  test('reports route contract and async hazards', () {
    const String source = '''
from fastapi import Body, FastAPI, HTTPException
import requests
app = FastAPI()
@app.get("/search")
async def search(payload: dict = Body(...)):
    requests.get("https://example.test")
    try:
        return {"ok": True}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
@app.delete("/users/{id}", status_code=204)
def remove_user(id: int):
    return {"removed": id}
''';
    final Map<String, String> sources = <String, String>{'app/api.py': source};
    for (final String id in <String>[
      'fastapi-route-missing-response-model',
      'fastapi-route-status-code-mismatch',
      'fastapi-route-body-with-get',
      'fastapi-unvalidated-dict-body',
      'fastapi-sync-blocking-route',
      'fastapi-broad-http-exception',
      'fastapi-sensitive-error-detail',
      'fastapi-missing-error-response-docs',
    ]) {
      expect(run(id, sources), isNotEmpty, reason: id);
    }
  });

  test('reports explicit authentication and transport hazards', () {
    const String source = '''
from fastapi import FastAPI
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
import jwt
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app.add_middleware(CORSMiddleware, allow_origins=["*"])
@app.post("/users")
def create_user(payload: UserIn):
    user = db.query(User).get(payload.id)
    if not current_user.is_admin:
        deny()
    password = payload.password
    return jwt.decode(payload.token, SECRET)
''';
    final Map<String, String> sources = <String, String>{'app/api.py': source};
    for (final String id in <String>[
      'fastapi-missing-auth-dependency',
      'fastapi-role-check-after-resource-access',
      'fastapi-plaintext-password',
      'fastapi-insecure-jwt-decode',
      'fastapi-permissive-cors',
    ]) {
      expect(run(id, sources), isNotEmpty, reason: id);
    }
  });

  test('reports project security boundary gaps and raw request logging', () {
    const String source = '''
from fastapi import FastAPI
app = FastAPI()
@app.get("/a")
def a(request):
    logger.info(request.headers)
    return None
@app.get("/b")
def b(): return None
@app.get("/c")
def c(): return None
@app.get("/d")
def d(): return None
@app.get("/e")
def e(): return None
''';
    final Map<String, String> sources = <String, String>{'app/api.py': source};
    expect(run('fastapi-missing-rate-limit', sources), hasLength(1));
    expect(run('fastapi-missing-security-headers', sources), hasLength(1));
    expect(run('fastapi-request-data-logging', sources), hasLength(1));
  });

  test('reports database lifecycle and query hazards', () {
    const String source = '''
def get_db():
    session = SessionLocal()
    yield session

def save(items):
    try:
        session.commit()
    except DatabaseError:
        raise
    for item in items:
        session.query(Item).get(item.id)
    return session.query(Item).all()
''';
    final Map<String, String> sources = <String, String>{'app/db.py': source};
    for (final String id in <String>[
      'fastapi-db-session-not-closed',
      'fastapi-transaction-without-rollback',
      'fastapi-query-in-loop',
      'fastapi-unbounded-query',
    ]) {
      expect(run(id, sources), isNotEmpty, reason: id);
    }
  });

  test(
    'reports heavy background work, mutable cache, sprawl, and settings bypass',
    () {
      const String source = '''
from pydantic_settings import BaseSettings
from fastapi import FastAPI, BackgroundTasks
import os
app = FastAPI()
user_cache = {}
@app.get("/users")
def users(): return []
@app.post("/users")
def create_user(background_tasks: BackgroundTasks):
    background_tasks.add_task(process_video, "input.mp4")
    return os.getenv("REGION")
@app.get("/orders")
def orders(): return []
@app.post("/orders")
def create_order(): return None
@app.get("/reports")
def reports(): return []
@app.post("/reports")
def create_report(): return None
class Settings(BaseSettings):
    region: str
''';
      final Map<String, String> sources = <String, String>{
        'app/api.py': source,
      };
      for (final String id in <String>[
        'fastapi-background-task-heavy-work',
        'fastapi-global-mutable-cache',
        'fastapi-route-domain-sprawl',
        'fastapi-settings-bypass',
      ]) {
        expect(run(id, sources), isNotEmpty, reason: id);
      }
    },
  );

  test('reports a changed route without a related changed API test', () {
    const Map<String, String> sources = <String, String>{
      'app/users.py': '''
from fastapi import APIRouter
router = APIRouter()
@router.get("/users/{id}")
def read_user(id: int):
    return User(id=id)
''',
    };
    expect(
      run(
        'fastapi-route-without-integration-test',
        sources,
        changedPaths: const <String>{'app/users.py'},
        changedMode: true,
      ),
      hasLength(1),
    );
    expect(
      run(
        'fastapi-route-without-integration-test',
        sources,
        changedPaths: const <String>{'app/users.py', 'tests/api/test_users.py'},
        changedMode: true,
      ),
      isEmpty,
    );
  });

  test('accepts explicit safe FastAPI contracts', () {
    const Map<String, String> sources = <String, String>{
      'app/api.py': '''
from fastapi import APIRouter, Depends
router = APIRouter()
@router.get("/users/{id}", response_model=UserOut, responses={404: {"model": Error}})
async def read_user(id: int, principal: User = Depends(get_current_user)) -> UserOut:
    if not principal.can_read(id):
        raise HTTPException(status_code=404, detail="not found")
    return await repository.get_user(id)
''',
    };
    for (final String id in <String>[
      'fastapi-route-missing-response-model',
      'fastapi-route-body-with-get',
      'fastapi-unvalidated-dict-body',
      'fastapi-sync-blocking-route',
      'fastapi-missing-auth-dependency',
      'fastapi-sensitive-error-detail',
      'fastapi-missing-error-response-docs',
    ]) {
      expect(run(id, sources), isEmpty, reason: id);
    }
  });
}
