import Joi from 'joi';

const validateSecurityEvent = (data) => {
  const schema = Joi.object({
    eventType: Joi.string().required(),
    data: Joi.object().required(),
    severity: Joi.string().valid('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
  });

  return schema.validate(data);
};

const validateBlockRequest = (data) => {
  const schema = Joi.object({
    deviceId: Joi.string().required(),
    reason: Joi.string().required()
  });

  return schema.validate(data);
};

export { validateSecurityEvent, validateBlockRequest };
