module.exports = function ( grunt ) {

  require( 'load-grunt-tasks' )( grunt );

  var path = require( 'path' );
  var phpspecPath = path.normalize('vendor/bin/phpspec');

  grunt.registerTask( 'default', [
    'clear',
    'shell:phpspec',
    'watch'
  ] );

  grunt.initConfig( {
    watch: {
      phpspec: {
        files: ['{src,spec}/**/*.php'],
        tasks: ['clear', 'shell:phpspec']
      }
    },
    shell: {
      phpspec: {
        command: phpspecPath + ' run -n --ansi',
        options: {
          stdout: true
        }
      }
    }
  } );

};
