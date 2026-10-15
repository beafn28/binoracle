# Imagen del laboratorio efimero de Drupal: la oficial drupal:10-apache NO trae Drush (a
# diferencia de la imagen wordpress:cli que SI existe para WordPress), asi que se añade aqui en
# tiempo de build -- una sola vez, cacheada por Docker despues (mismo patron que "se pulls
# wordpress/mysql/alpine en el primer uso" de wpverify.py, pero via build en vez de pull, porque
# no existe un equivalente publico "drupal:cli"). Necesita internet SOLO en este build, nunca en
# tiempo de ejecucion del laboratorio.
FROM drupal:10-apache
WORKDIR /opt/drupal
RUN composer require drush/drush:^12 --no-interaction --no-progress && composer clear-cache
