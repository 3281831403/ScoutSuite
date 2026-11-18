import asyncio

from ScoutSuite import ERRORS_LIST
from ScoutSuite.core.console import print_exception, print_debug, print_info, fetching_service
from ScoutSuite.providers.aws.utils import get_partition_name
from ScoutSuite.utils import format_service_name


class BaseServicesConfig:

    def __init__(self, credentials):
        self.credentials = credentials
        # Per-service collection outcome, populated by fetch():
        # {service: {'errors': [<error message>, ...], 'fetch_failed': <bool>}}
        # 'fetch_failed' is True when the service-level fetch raised (nothing
        # usable was collected); a service with 'errors' but no failure was
        # only partially collected (e.g. a throttled region).
        self.fetch_errors = {}

    def _is_provider(self, provider_name):
        return False

    async def fetch(self, services: list, regions: list, excluded_regions: list):

        if not services:
            print_debug('No services to scan')
        else:
            # Remove "credentials" as it isn't a service
            if 'credentials' in services:
                services.remove('credentials')

            # Print services that are going to get skipped:
            for service in vars(self):
                if service not in services and service not in ['credentials', 'fetch_errors']:
                    print_debug('Skipping the {} service'.format(format_service_name(service)))

            # Then, fetch concurrently all services:
            if services:
                errors_before = len(ERRORS_LIST)
                tasks = {
                    asyncio.ensure_future(
                        self._fetch(service, regions, excluded_regions)
                    ) for service in services
                }
                await asyncio.wait(tasks)
                # Attribute the exceptions handled while each service fetch was
                # in flight (tagged via the fetching_service context variable)
                # to the service being collected when they occurred
                for error in ERRORS_LIST[errors_before:]:
                    service = error.get('service')
                    if service:
                        service_errors = self.fetch_errors.setdefault(
                            service, {'errors': [], 'fetch_failed': False})
                        service_errors['errors'].append(error['exception'])

    async def _fetch(self, service, regions=None, excluded_regions=None):
        token = fetching_service.set(service)
        try:
            print_info('Fetching resources for the {} service'.format(format_service_name(service)))
            service_config = getattr(self, service)
            # call fetch method for the service
            if 'fetch_all' in dir(service_config):
                method_args = {}

                if regions:
                    method_args['regions'] = regions
                if excluded_regions:
                    method_args['excluded_regions'] = excluded_regions

                if self._is_provider('aws'):
                    if service != 'iam':
                        method_args['partition_name'] = get_partition_name(self.credentials.session)

                await service_config.fetch_all(**method_args)
                if hasattr(service_config, 'finalize'):
                    await service_config.finalize()
            else:
                print_debug(f'No method to fetch service {service}.')
        except Exception as e:
            print(e) # for debugging
            print_exception(f'Could not fetch {format_service_name(service)} configuration: {e}')
            service_errors = self.fetch_errors.setdefault(
                service, {'errors': [], 'fetch_failed': False})
            service_errors['fetch_failed'] = True
        finally:
            fetching_service.reset(token)
