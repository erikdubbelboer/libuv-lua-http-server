{
  'targets': [
    {
      'target_name': 'parson',
      'type': 'static_library',
      'sources': [
        'parson.c'
      ],
      'include_dirs': [
        '.'
      ],
      'direct_dependent_settings': {
        'include_dirs': [
          '.'
        ]
      }
    }
  ]
}
