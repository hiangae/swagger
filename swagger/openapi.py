import frappe
import os
import re
import json
import ast
import inspect
import importlib.util
from werkzeug.wrappers import Response
from pydantic import BaseModel
from typing import get_type_hints

ANNOTATIONS = {'str': 'string', 'bool':'boolean', 'int' : 'integer', 'float':'float', 'dict':'object', 'list':'array' }


@frappe.whitelist()
def openapi_json(*arg, **kwargs):
	"""
		OPEN API JSON 정보를 제공합니다.
	"""
	
	swagger_settings = frappe.get_single("Swagger Settings")
	
	# OPEN API 사양서 초기화
	swagger = {
		"openapi": "3.0.0",
		"info": {
			"title": f"{swagger_settings.app_name} API",
			"version": "1.0.0",
		},
		"paths": {},
		"components": {},
	}
	
	if swagger_settings.token_based_basicauth or swagger_settings.bearerauth:
		swagger["components"]["securitySchemes"] = {}
		swagger["security"] = []
	
	if swagger_settings.token_based_basicauth:
		swagger["components"]["securitySchemes"]["basicAuth"] = {
			"type": "http",
			"scheme": "basic",
		}
		swagger["security"].append({"basicAuth": []})

	if swagger_settings.bearerauth:
		swagger["components"]["securitySchemes"]["bearerAuth"] = {
			"type": "http",
			"scheme": "bearer",
			"bearerFormat": "JWT",
		}
		swagger["security"].append({"bearerAuth": []})
	
	frappe_bench_dir = frappe.utils.get_bench_path()
	file_paths = []
	
	# 설치앱의 api 폴더 검색
	for app in frappe.get_installed_apps():
		if app in ["frappe", "swagger"] : continue
		try:
			api_dir = os.path.join(frappe_bench_dir, "apps", app, app, "api")
			if os.path.exists(api_dir) and os.path.isdir(api_dir):
				for root, dirs, files in os.walk(api_dir):
					for file in files:
						if file.endswith(".py"):
							file_paths.append((app,os.path.join(root, file)))
		except Exception as e:
			frappe.log_error(f"Error processing app '{app}': {str(e)}")
			continue
	
	# py 파일 로드
	for app, file_path in file_paths:
		try:
			if os.path.isfile(file_path) and app in str(file_path):
				module = load_module_from_file(file_path)
				module_name = os.path.basename(file_path).replace(".py", "")
				for func_name, func in inspect.getmembers(module, inspect.isfunction):
					# 외부에서 가져온 모듈의 함수는 제외
					if module_name == func.__module__:
						process_function(app, module_name, func_name, func, swagger, module)
			else:
				print(f"File not found: {file_path}")
		except Exception as e:
			frappe.log_error(f"{str(e)}")
	
	swagger_json = json.dumps(swagger, indent=2)
	return Response(swagger_json)


def load_module_from_file(file_path):
	""" 파일에서 동적으로 모듈을 로딩 """
	
	module_name = os.path.basename(file_path).replace(".py", "")
	spec = importlib.util.spec_from_file_location(module_name, file_path)
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module


def find_decorator(tree):
	""" 트리에서 데코레이터 확인 """
	
	for n in ast.walk(tree):
		if isinstance(n, ast.FunctionDef):
			for decorator in n.decorator_list:
				if isinstance(decorator, ast.Call):
					if decorator.func.attr == "whitelist":
						return decorator
	return None


def process_function(app_name, module_name, func_name, func, swagger, module):
	""" 모듈에 있는 함수에서 whitelist 체크 """
	
	try:
		source_code = inspect.getsource(func)
		tree = ast.parse(source_code)
		
		if not any("whitelist" in ast.dump(node) and isinstance(node, ast.Call) for node in ast.walk(tree)): return
		
		decorator = find_decorator(tree)
		if not decorator : return 
		
		# api 호출 경로
		path = f"/api/method/{app_name}.api.{module_name}.{func_name}".lower()
		
		# 함수 파라미터 정보
		params = []
		
		# 함수 시그니쳐 확인 (Annotation & Default)
		signature = inspect.signature(func)
		
		for param_name, param in signature.parameters.items():
			if (not param_name in ["args", "kwargs"]):
				param_type = ANNOTATIONS.get(param.annotation.__name__, 'string')
				required = True if param.default == inspect.Parameter.empty else False
				params.append({
						"name": param_name,
						"in": "query",
						"required": required,
						"schema": {"type": param_type},
					})
		
		# 요청
		request_body = {}
		
		# 문서 설명정보
		description = inspect.getdoc(func)

		# 태그 설정
		tags = [module_name]

		# 응답 스키마
		responses = {
			"200": {
				"description": "Successful response",
				"content": {"application/json": {"schema": {"type": "object" }}},
			}
		}

		# 스웨거 경로에 없을 경우 초기화
		if path not in swagger["paths"]:
			swagger["paths"][path] = {}
		
		# 파라미터가 있는 경우만 POST
		method = 'post' if params else 'get'
		
		swagger["paths"][path][method] = {
			"summary": func_name.title().replace("_", " "),
			"tags": tags,
			"parameters": params,
			"requestBody": request_body,
			"responses": responses,
			"security": [{"basicAuth": []}],
			"description": description,
		}

	except Exception as e:
		frappe.log_error(f"Error processing function {func_name} in module {module_name}: {str(e)}")


def get_pydantic_model_schema(model_name, module):
	if hasattr(module, model_name):
		model = getattr(module, model_name)
		if issubclass(model, BaseModel):
			return model.model_json_schema()
	return None